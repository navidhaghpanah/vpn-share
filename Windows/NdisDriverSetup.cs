using System.Diagnostics;
using System.Security.Cryptography;

namespace VpnShare;

public static class NdisDriverSetup
{
    public const string FileName="Windows.Packet.Filter.3.6.2.1.x64.msi";
    public const string Sha256="9C388C0B7F189F7FA98720BAE2CAECF7D64F30910838B80B438ECF8956B8502C";
    public const string DownloadUrl="https://github.com/wiresock/ndisapi/releases/download/v3.6.2/Windows.Packet.Filter.3.6.2.1.x64.msi";
    public static void VerifyDigest(Stream file)
    {
        if(Convert.ToHexString(SHA256.HashData(file))!=Sha256)throw new InvalidDataException("The official packet-driver installer failed its SHA-256 integrity check.");
    }
    public static async Task EnsureInstalled(CancellationToken token)
    {
        if(NdisDevice.Available)return;
        string directory=ProtectedStorage.NewStagingDirectory(),path=Path.Combine(directory,FileName);
        string log=Path.Combine(directory,"install.log");
        try{
            string local=Path.Combine(AppContext.BaseDirectory,FileName);
            await using(var destination=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None)){
                if(File.Exists(local)){
                    await using var source=File.OpenRead(local);if(source.Length>16*1024*1024)throw new InvalidDataException("Installer exceeds the size limit.");await source.CopyToAsync(destination,token);
                }else{
                    using var client=new HttpClient{Timeout=TimeSpan.FromMinutes(3)};
                    using var response=await client.GetAsync(DownloadUrl,HttpCompletionOption.ResponseHeadersRead,token);response.EnsureSuccessStatusCode();
                    if(response.Content.Headers.ContentLength>16*1024*1024)throw new InvalidDataException("Installer exceeds the size limit.");
                    await using var source=await response.Content.ReadAsStreamAsync(token);var buffer=new byte[65536];int total=0,count;
                    while((count=await source.ReadAsync(buffer,token))>0){total+=count;if(total>16*1024*1024)throw new InvalidDataException("Installer exceeds the size limit.");await destination.WriteAsync(buffer.AsMemory(0,count),token);}
                }
            }
            ProtectedStorage.CheckFile(path);
            // Keep the protected, verified file open with write/delete sharing
            // denied until msiexec exits. Signature checking and MSI may read it.
            using var verified=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read);VerifyDigest(verified);
            string quoted="'"+path.Replace("'","''")+"'";
            await Task.Run(()=>NetworkSetup.Run("$s=Get-AuthenticodeSignature -LiteralPath "+quoted+"; if($s.Status -ne 'Valid'){throw 'The official driver installer signature is not trusted on this computer.'}"),token);
            token.ThrowIfCancellationRequested();
            var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),"System32","msiexec.exe")){UseShellExecute=false,CreateNoWindow=true};
            foreach(var item in new[]{"/i",path,"/passive","/norestart","/L*v",log})start.ArgumentList.Add(item);
            using var process=Process.Start(start)??throw new InvalidOperationException("The driver installer could not start.");
            await process.WaitForExitAsync();
            if(process.ExitCode==3010)throw new InvalidOperationException("The signed driver was installed. Windows requires a restart before sharing can begin. Save your work and restart manually.");
            if(process.ExitCode!=0)throw new InvalidOperationException($"The driver installer returned {process.ExitCode}. See {log}");
            token.ThrowIfCancellationRequested();
            if(!NdisDevice.Available)throw new InvalidOperationException("The installed packet device cannot be opened. Check Windows Security and the installation log. No sharing configuration was changed.");
        }finally{
            // Exact owned file only. Keep a failed installation log for diagnosis.
            try{File.Delete(path);if(!File.Exists(log))Directory.Delete(directory);}catch{}
        }
    }
}
