namespace VpnShare;

public static class SecuritySelfTest
{
    public static object Run()
    {
        string directory=ProtectedStorage.NewStagingDirectory(),path=Path.Combine(directory,"probe.bin");
        bool writeBlocked=false,deleteBlocked=false;
        try{
            using(var created=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None))created.Write(new byte[]{1,2,3,4});
            ProtectedStorage.CheckFile(path);
            using(var verified=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.Read)){
                try{using var writer=new FileStream(path,FileMode.Open,FileAccess.Write,FileShare.ReadWrite);}catch(IOException){writeBlocked=true;}
                try{File.Delete(path);}catch(IOException){deleteBlocked=true;}
            }
            if(!writeBlocked||!deleteBlocked)throw new InvalidOperationException("Verified installer file locking did not protect the test file.");
            return new{Passed=true,PrivateDirectory=true,TrustedFileOwnerAndAcl=true,WriteBlocked=writeBlocked,DeleteBlocked=deleteBlocked,AbsoluteSystemHelper=Path.IsPathFullyQualified(NetworkSetup.PowerShellPath)};
        }finally{File.Delete(path);Directory.Delete(directory);}
    }
}
