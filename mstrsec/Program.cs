namespace mstrsec
{
    using System.IO;
    using System.Security.AccessControl;

    class Program
    {
        private static MstrAcl _acl = new MstrAcl();

        static void Main(string[] args)
        {
            if (args.Length == 2)
            {
                var username = args[0];
                var path = args[1];

                _acl.HomeFolderPermission(username, path);
                System.Console.WriteLine("Success");
            }
            else
            {
                System.Console.WriteLine("Invalid Argument\r\n");
                System.Console.WriteLine("\tMaestroPanel ACL Template");
                System.Console.WriteLine("\tOğuzhan YILMAZ - oguzhan@maestropanel.com");
                System.Console.WriteLine("\tUsage: mstrsec.exe [USERNAME] [PATH]");
                System.Console.WriteLine("\tExample: mstrsec.exe hakan C:\\vhosts\\domain.com\\http");
            }
        }
    }

    public class MstrAcl
    {
        public void RootFolderPermission(string username, string path)
        {
            DirectorySecurity sec = Directory.GetAccessControl(path);
            sec.AddAccessRule(new FileSystemAccessRule(username, FileSystemRights.Read,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            Directory.SetAccessControl(path, sec);
        }


        public void HomeFolderPermission(string username, string path)
        {
            DirectorySecurity sec = Directory.GetAccessControl(path);

            sec.AddAccessRule(new FileSystemAccessRule(username, FileSystemRights.Modify, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));

            sec.AddAccessRule(new FileSystemAccessRule(username, FileSystemRights.DeleteSubdirectoriesAndFiles,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None,
                AccessControlType.Allow));

            sec.AddAccessRule(new FileSystemAccessRule(username, FileSystemRights.Delete, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                   PropagationFlags.None, AccessControlType.Deny));

            Directory.SetAccessControl(path, sec);
        }
    }
}
