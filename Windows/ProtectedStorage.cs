using System.Security.AccessControl;
using System.Security.Principal;

namespace VpnShare;

public static class ProtectedStorage
{
    const string Administrators="S-1-5-32-544",SystemAccount="S-1-5-18";
    public static string Root=>Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),"VPNShare");
    static bool TrustedOwner(string? sid)=>sid is Administrators or SystemAccount;
    static DirectorySecurity DirectoryAcl()
    {
        var acl=new DirectorySecurity();acl.SetAccessRuleProtection(true,false);acl.SetOwner(new SecurityIdentifier(Administrators));
        foreach(var sid in new[]{Administrators,SystemAccount})acl.AddAccessRule(new FileSystemAccessRule(new SecurityIdentifier(sid),FileSystemRights.FullControl,InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,PropagationFlags.None,AccessControlType.Allow));
        return acl;
    }
    public static string EnsureDirectory(string path)
    {
        if(!new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))throw new UnauthorizedAccessException("Protected network state requires Administrator permission.");
        var directory=new DirectoryInfo(path);
        // Create with its final restrictive descriptor, not a permissive mkdir
        // followed by an ACL change. Recheck any preexisting object afterward.
        if(!directory.Exists)directory.Create(DirectoryAcl());
        directory.Refresh();
        if((directory.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("Protected state cannot be a reparse point.");
        var acl=directory.GetAccessControl();if(!TrustedOwner(acl.GetOwner(typeof(SecurityIdentifier))?.Value))throw new InvalidOperationException("Protected state has an untrusted owner.");
        directory.SetAccessControl(DirectoryAcl());return directory.FullName;
    }
    public static void CheckFile(string path)
    {
        var file=new FileInfo(path);file.Refresh();
        if(!file.Exists)throw new FileNotFoundException("Protected file is missing.",path);
        if((file.Attributes&FileAttributes.ReparsePoint)!=0)throw new InvalidOperationException("Protected files cannot be reparse points.");
        var acl=file.GetAccessControl();if(!TrustedOwner(acl.GetOwner(typeof(SecurityIdentifier))?.Value))throw new InvalidOperationException("Protected file has an untrusted owner.");
        const FileSystemRights writes=FileSystemRights.WriteData|FileSystemRights.AppendData|FileSystemRights.ChangePermissions|FileSystemRights.TakeOwnership|FileSystemRights.Delete;
        foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier)))
            if(rule.AccessControlType==AccessControlType.Allow&&(rule.FileSystemRights&writes)!=0&&!TrustedOwner(rule.IdentityReference.Value))throw new InvalidOperationException("Protected file grants write access to an untrusted principal.");
    }
    public static string NewStagingDirectory()
    {
        EnsureDirectory(Root);
        return EnsureDirectory(Path.Combine(Root,"driver-"+Guid.NewGuid().ToString("N")));
    }
}
