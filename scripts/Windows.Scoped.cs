using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;

// Selected ordinary files only. This adapter is separate from legacy owned-run cleanup.
namespace PatchCairn {
 public sealed class ScopedRecord {
  public string relative_path,kind,inode,sha256; public long device,mode,size,mtime_ns,ctime_ns,nlink,attributes;
 }
 public static class WindowsScoped {
  [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write; public uint Volume,SizeHigh,SizeLow,Links,IdHigh,IdLow; }
  [StructLayout(LayoutKind.Sequential)] struct Disposition { [MarshalAs(UnmanagedType.Bool)] public bool DeleteFile; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder p,uint n,uint flags);
  [DllImport("kernel32.dll",SetLastError=true)] static extern uint GetFileType(SafeFileHandle h);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(SafeFileHandle h,byte[] b,int count,out int read,IntPtr overlap);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool WriteFile(SafeFileHandle h,byte[] b,int count,out int written,IntPtr overlap);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool FlushFileBuffers(SafeFileHandle h);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFilePointerEx(SafeFileHandle h,long offset,out long position,uint method);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int cls,IntPtr buffer,uint size);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int cls,ref Disposition value,uint size);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateDirectoryW(string path,IntPtr security);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern uint GetDriveTypeW(string root);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool GetVolumeInformationByHandleW(SafeFileHandle h,StringBuilder volume,uint volumeSize,out uint serial,out uint componentLength,out uint flags,StringBuilder filesystem,uint filesystemSize);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFileAttributesW(string path);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern IntPtr GetModuleHandleW(string name);
  [DllImport("kernel32.dll",CharSet=CharSet.Ansi,ExactSpelling=true,SetLastError=true)] static extern IntPtr GetProcAddress(IntPtr module,string name);
  [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {public uint Length;public IntPtr Descriptor;[MarshalAs(UnmanagedType.Bool)]public bool Inherit;}
  [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
  [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr memory);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool OpenProcessToken(IntPtr process,uint access,out SafeFileHandle token);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetTokenInformation(SafeFileHandle token,int kind,IntPtr buffer,uint length,out uint needed);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertSidToStringSidW(IntPtr sid,out IntPtr value);
  [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string value,uint revision,out IntPtr descriptor,out uint length);
  [DllImport("advapi32.dll",SetLastError=true)] static extern uint GetSecurityInfo(SafeFileHandle handle,int kind,uint information,out IntPtr owner,IntPtr group,out IntPtr dacl,IntPtr sacl,out IntPtr descriptor);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetSecurityDescriptorControl(IntPtr descriptor,out ushort control,out uint revision);
  [DllImport("advapi32.dll")] static extern bool IsValidSid(IntPtr sid);
  [DllImport("advapi32.dll")] static extern uint GetLengthSid(IntPtr sid);
  [DllImport("advapi32.dll")] static extern bool IsValidAcl(IntPtr acl);
  [DllImport("advapi32.dll",SetLastError=true)] static extern bool GetAce(IntPtr acl,uint index,out IntPtr ace);
  const uint DirectoryBit=0x10, Reparse=0x400, Unsupported=0x1000|0x4000|0x40000|0x400000;
  const long FileCap=68719476736L; // Per-file hash/read bound, caller normally chooses much less.
  static void Refuse(string code) { throw new InvalidOperationException("scoped:"+code); }
  static void Native(bool ok,string code) { if(!ok)Refuse(code); }
  public static void CheckCapabilities() {
   IntPtr module=GetModuleHandleW("kernel32.dll");
   foreach(string name in new string[]{"CreateFileW","GetFileInformationByHandle","GetFinalPathNameByHandleW","GetVolumeInformationByHandleW","SetFileInformationByHandle","ReadFile","WriteFile","FlushFileBuffers"})
    if(module==IntPtr.Zero||GetProcAddress(module,name)==IntPtr.Zero)Refuse("native-api-unavailable");
  }
  // Creation-time security only. No API to change an existing object's owner/DACL.
  sealed class PrivateCreation:IDisposable {
   IntPtr tokenBuffer=IntPtr.Zero,descriptor=IntPtr.Zero,attributes=IntPtr.Zero;
   string user;HashSet<string> principals;
   public IntPtr Attributes {get{return attributes;}}
   static string SidText(IntPtr sid) {
    if(sid==IntPtr.Zero||!IsValidSid(sid))Refuse("new-private-creator-unavailable");
    IntPtr text=IntPtr.Zero;Native(ConvertSidToStringSidW(sid,out text),"new-private-creator-unavailable");
    try{return Marshal.PtrToStringUni(text);}finally{if(text!=IntPtr.Zero)LocalFree(text);}
   }
   public PrivateCreation() {
    try {
     SafeFileHandle token;Native(OpenProcessToken(GetCurrentProcess(),8,out token),"new-private-creator-unavailable");
     using(token) {
      uint length;GetTokenInformation(token,1,IntPtr.Zero,0,out length);
      if(length<8||length>65536)Refuse("new-private-creator-unavailable");
      tokenBuffer=Marshal.AllocHGlobal((int)length);
      Native(GetTokenInformation(token,1,tokenBuffer,length,out length),"new-private-creator-unavailable");
      user=SidText(Marshal.ReadIntPtr(tokenBuffer));
     }
     principals=new HashSet<string>(new string[]{user,"S-1-5-18","S-1-5-32-544"},StringComparer.Ordinal);
     string sddl="O:"+user+"D:P"+String.Join("",principals.Select(s=>"(A;;FA;;;"+s+")"));
     uint bytes;Native(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl,1,out descriptor,out bytes),"new-private-descriptor-unavailable");
     if(bytes==0||bytes>65536)Refuse("new-private-descriptor-unavailable");
     SecurityAttributes value=new SecurityAttributes{Length=(uint)Marshal.SizeOf(typeof(SecurityAttributes)),Descriptor=descriptor,Inherit=false};
     attributes=Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SecurityAttributes)));Marshal.StructureToPtr(value,attributes,false);
    } catch {Dispose();throw;}
   }
   public void Validate(SafeFileHandle handle) {
    IntPtr owner=IntPtr.Zero,dacl=IntPtr.Zero,actual=IntPtr.Zero;
    try {
     if(GetSecurityInfo(handle,1,5,out owner,IntPtr.Zero,out dacl,IntPtr.Zero,out actual)!=0||actual==IntPtr.Zero||dacl==IntPtr.Zero)Refuse("new-private-file-security-unresolved");
     ushort control;uint revision;
     Native(GetSecurityDescriptorControl(actual,out control,out revision),"new-private-file-security-unresolved");
     if((control&0x1004)!=0x1004||SidText(owner)!=user||!IsValidAcl(dacl))Refuse("new-private-file-security-unresolved");
     uint count=(ushort)Marshal.ReadInt16(dacl,4);if(count!=principals.Count)Refuse("new-private-file-security-unresolved");
     HashSet<string> seen=new HashSet<string>(StringComparer.Ordinal);
     for(uint index=0;index<count;index++) {
      IntPtr ace;Native(GetAce(dacl,index,out ace),"new-private-file-security-unresolved");
      uint size=(ushort)Marshal.ReadInt16(ace,2);
      if(Marshal.ReadByte(ace,0)!=0||Marshal.ReadByte(ace,1)!=0||size<16||(uint)Marshal.ReadInt32(ace,4)!=0x1f01ff)Refuse("new-private-file-security-unresolved");
      IntPtr sid=IntPtr.Add(ace,8);if(!IsValidSid(sid)||GetLengthSid(sid)>size-8)Refuse("new-private-file-security-unresolved");
      string principal=SidText(sid);if(!principals.Contains(principal)||!seen.Add(principal))Refuse("new-private-file-security-unresolved");
     }
    } catch {throw new InvalidOperationException("scoped:new-private-file-security-unresolved");}
    finally {if(actual!=IntPtr.Zero)LocalFree(actual);}
   }
   public void Dispose() {
    if(attributes!=IntPtr.Zero){Marshal.FreeHGlobal(attributes);attributes=IntPtr.Zero;}
    if(descriptor!=IntPtr.Zero){LocalFree(descriptor);descriptor=IntPtr.Zero;}
    if(tokenBuffer!=IntPtr.Zero){Marshal.FreeHGlobal(tokenBuffer);tokenBuffer=IntPtr.Zero;}
   }
  }
  static string Full(string path) {
   if(String.IsNullOrEmpty(path)||path.Length>240||path.IndexOf('/')>=0||path.StartsWith("\\\\")||path.Length<4||!Char.IsLetter(path[0])||path[1]!=':'||path[2]!='\\')Refuse("local-absolute-root-required");
   string p=Path.GetFullPath(path).TrimEnd('\\');
   if(!String.Equals(p,path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))Refuse("noncanonical-root");
   foreach(string part in p.Substring(3).Split('\\'))Leaf(part);
   if(GetDriveTypeW(p.Substring(0,3))!=3)Refuse("fixed-local-volume-required");return p;
  }
  static void Leaf(string part) {
   if(String.IsNullOrEmpty(part)||part=="."||part==".."||part.EndsWith(".")||part.EndsWith(" ")||part.IndexOfAny(new char[]{':','\\','/','*','?','<','>','|','"'})>=0||part.Any(c=>c<32))Refuse("invalid-path-component");
   string stem=part.Split('.')[0];if(System.Text.RegularExpressions.Regex.IsMatch(stem,@"\A(CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])\z",System.Text.RegularExpressions.RegexOptions.IgnoreCase))Refuse("reserved-path-component");
  }
  static string Relative(string relative,bool allowRoot) {
   if(relative==null||(!allowRoot&&relative.Length==0)||relative.Length>200||relative.Contains("\\")||relative.Split('/').Length>64)Refuse("invalid-relative-path");
   if(relative.Length>0)foreach(string p in relative.Split('/'))Leaf(p);return relative;
  }
  static Info Metadata(SafeFileHandle h) { Info i;Native(GetFileInformationByHandle(h,out i),"metadata-unavailable");return i; }
  static void Exact(SafeFileHandle h,string path) {
   StringBuilder b=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(h,b,(uint)b.Capacity,0);
   if(n==0||n>=b.Capacity)Refuse("canonical-path-unavailable");string p=b.ToString();
   if(!p.StartsWith("\\\\?\\")||p.StartsWith("\\\\?\\UNC\\",StringComparison.OrdinalIgnoreCase))Refuse("unexpected-canonical-path");
   if(!String.Equals(p.Substring(4).TrimEnd('\\'),path.TrimEnd('\\'),StringComparison.OrdinalIgnoreCase))Refuse("canonical-path-mismatch");
  }
  static SafeFileHandle Open(string path,bool? directory,bool mutation) {
   SafeFileHandle h=CreateFileW(path,0x80u|1u|(mutation?0x10000u:0u),directory==true?3u:1u,IntPtr.Zero,3,0x02200000u,IntPtr.Zero);
   if(h.IsInvalid){int error=Marshal.GetLastWin32Error();h.Dispose();if(error==2&&directory!=true)Refuse("missing-entry");Refuse("access-sharing-or-missing");}
   try {Exact(h,path);Info i=Metadata(h);if(GetFileType(h)!=1)Refuse("non-disk-file");if((i.Attributes&Reparse)!=0)Refuse("reparse-point");if((i.Attributes&Unsupported)!=0)Refuse("offline-encrypted-or-recall-file");bool d=(i.Attributes&DirectoryBit)!=0;if(directory.HasValue&&d!=directory.Value)Refuse("unexpected-type");if(!d&&i.Links!=1)Refuse("hardlink");if(mutation&&(i.Attributes&5)!=0)Refuse("readonly-or-system-file");return h;}catch{h.Dispose();throw;}
  }
  static long Time(System.Runtime.InteropServices.ComTypes.FILETIME t) {return ((((long)t.dwHighDateTime<<32)|(uint)t.dwLowDateTime)-116444736000000000L)*100L;}
  static ScopedRecord Record(string relative,SafeFileHandle h) {Info i=Metadata(h);bool d=(i.Attributes&DirectoryBit)!=0;return new ScopedRecord{relative_path=relative,kind=d?"directory":"file",device=i.Volume,inode=i.IdHigh.ToString("x8")+i.IdLow.ToString("x8"),mode=i.Attributes,size=d?0:((long)i.SizeHigh<<32)|i.SizeLow,mtime_ns=Time(i.Write),ctime_ns=Time(i.Creation),nlink=i.Links,attributes=i.Attributes,sha256=null};}
  static bool Same(ScopedRecord a,ScopedRecord b,bool identityOnly) {return a!=null&&b!=null&&a.kind==b.kind&&a.device==b.device&&a.inode==b.inode&&a.ctime_ns==b.ctime_ns&&a.attributes==b.attributes&&(identityOnly||(a.relative_path==b.relative_path&&a.size==b.size&&a.mtime_ns==b.mtime_ns&&a.nlink==b.nlink&&a.sha256==b.sha256));}
  static string Hash(SafeFileHandle h,long maximum,MemoryStream bytes) {
   if(maximum<0||maximum>FileCap)Refuse("invalid-byte-bound");long size=Record("",h).size;if(size>maximum)Refuse("file-byte-bound");long pos;Native(SetFilePointerEx(h,0,out pos,0),"seek-failed");
   using(SHA256 sha=SHA256.Create()){byte[] b=new byte[65536];long total=0;int n;while(true){Native(ReadFile(h,b,b.Length,out n,IntPtr.Zero),"read-failed");if(n==0)break;total+=n;if(total>maximum||total>size)Refuse("file-grew");sha.TransformBlock(b,0,n,b,0);if(bytes!=null)bytes.Write(b,0,n);}if(total!=size)Refuse("short-read");sha.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();}
  }
  static ScopedRecord Fresh(string relative,SafeFileHandle h,bool hash,long maximum) {ScopedRecord before=Record(relative,h);if(hash&&before.kind=="file")before.sha256=Hash(h,maximum,null);ScopedRecord after=Record(relative,h);after.sha256=before.sha256;if(!Same(before,after,false))Refuse("changed-during-read");return before;}
  static void Expected(ScopedRecord actual,ScopedRecord expected) {if(expected==null||expected.kind!="file"||String.IsNullOrEmpty(expected.sha256)||!System.Text.RegularExpressions.Regex.IsMatch(expected.sha256,"\\A[a-f0-9]{64}\\z")||!Same(actual,expected,false))Refuse("stale-identity-or-content");}
  sealed class Scope:IDisposable {
   public string Root;public ScopedRecord RootRecord;readonly List<SafeFileHandle> held=new List<SafeFileHandle>();
   public Scope(string root,ScopedRecord expectedRoot) {Root=Full(root);try{string cur=Root.Substring(0,3);held.Add(Open(cur,true,false));uint serial,componentLength,flags;StringBuilder fs=new StringBuilder(64);Native(GetVolumeInformationByHandleW(held[0],null,0,out serial,out componentLength,out flags,fs,(uint)fs.Capacity),"filesystem-capability-unavailable");if(fs.ToString()!="NTFS")Refuse("ntfs-required");foreach(string p in Root.Substring(3).Split('\\')){cur=Path.Combine(cur,p);held.Add(Open(cur,true,false));}RootRecord=Record("",held[held.Count-1]);if(expectedRoot!=null&&!Same(RootRecord,expectedRoot,true))Refuse("selected-root-changed");}catch{Dispose();throw;}}
   public string PathOf(string relative) {Relative(relative,true);string p=relative.Length==0?Root:Path.Combine(Root,relative.Replace('/','\\'));if(p.Length>240)Refuse("path-length-bound");return p;}
   public void Parents(string relative) {Relative(relative,false);string[] parts=relative.Split('/');string cur=Root;for(int i=0;i<parts.Length-1;i++){cur=Path.Combine(cur,parts[i]);held.Add(Open(cur,true,false));}}
   public void Dispose(){for(int i=held.Count-1;i>=0;i--)held[i].Dispose();held.Clear();}
  }
  public static ScopedRecord Inspect(string root,string relative,bool hash,long maximum,ScopedRecord expectedRoot) {using(Scope s=new Scope(root,expectedRoot)){if(relative.Length>0)s.Parents(relative);using(SafeFileHandle h=Open(s.PathOf(relative),null,false)){return Fresh(relative,h,hash,maximum);}}}
  public static ScopedRecord[] List(string root,string relative,int maxEntries,ScopedRecord expectedRoot) {
   if(maxEntries<1||maxEntries>20000)Refuse("invalid-entry-bound");using(Scope s=new Scope(root,expectedRoot)){if(relative.Length>0)s.Parents(relative);string p=s.PathOf(relative);using(SafeFileHandle parent=Open(p,true,false)){List<ScopedRecord> records=new List<ScopedRecord>();List<SafeFileHandle> children=new List<SafeFileHandle>();try{string[] paths=Directory.EnumerateFileSystemEntries(p).Take(maxEntries+1).OrderBy(x=>x,StringComparer.Ordinal).ToArray();if(paths.Length>maxEntries)Refuse("entry-bound");foreach(string child in paths){string leaf=Path.GetFileName(child);Leaf(leaf);SafeFileHandle h=Open(child,null,false);children.Add(h);records.Add(Fresh(relative.Length==0?leaf:relative+"/"+leaf,h,false,0));}string[] after=Directory.EnumerateFileSystemEntries(p).Take(maxEntries+1).OrderBy(x=>x,StringComparer.Ordinal).ToArray();if(!paths.SequenceEqual(after,StringComparer.Ordinal))Refuse("directory-membership-changed");return records.ToArray();}finally{foreach(SafeFileHandle h in children)h.Dispose();}}}
  }
  public static byte[] Read(string root,string relative,ScopedRecord expected,long maximum,ScopedRecord expectedRoot) {
   if(maximum>67108864)Refuse("memory-read-bound");using(Scope s=new Scope(root,expectedRoot)){s.Parents(relative);string p=s.PathOf(relative);using(SafeFileHandle h=Open(p,false,false)){ScopedRecord before=Fresh(relative,h,true,maximum);Expected(before,expected);using(MemoryStream m=new MemoryStream()){string hash=Hash(h,maximum,m);ScopedRecord after=Fresh(relative,h,true,maximum);Exact(h,p);if(hash!=before.sha256||!Same(before,after,false))Refuse("changed-during-read");return m.ToArray();}}}
  }
  public static ScopedRecord Move(string root,string relative,string destinationRoot,string destinationRelative,ScopedRecord expected,ScopedRecord expectedRoot,ScopedRecord expectedDestinationRoot) {
   using(Scope s=new Scope(root,expectedRoot))using(Scope d=new Scope(destinationRoot,expectedDestinationRoot)) {
    s.Parents(relative);d.Parents(destinationRelative);
    string source=s.PathOf(relative),target=d.PathOf(destinationRelative);
    if(!String.Equals(source.Substring(0,3),target.Substring(0,3),StringComparison.OrdinalIgnoreCase)||s.RootRecord.device!=d.RootRecord.device)Refuse("same-volume-required");
    if(String.Equals(source,target,StringComparison.OrdinalIgnoreCase))Refuse("same-path");
    using(SafeFileHandle h=Open(source,false,true)) {
     ScopedRecord before=Fresh(relative,h,true,FileCap);Expected(before,expected);
     byte[] name=Encoding.Unicode.GetBytes(target);int rootOffset=IntPtr.Size==8?8:4;
     int lengthOffset=rootOffset+IntPtr.Size,nameOffset=lengthOffset+4,length=nameOffset+name.Length+2;
     IntPtr buffer=Marshal.AllocHGlobal(length);
     try {
      for(int i=0;i<length;i++)Marshal.WriteByte(buffer,i,0);
      // ReplaceIfExists/Flags and RootDirectory stay zero; include NUL padding.
      Marshal.WriteInt32(buffer,lengthOffset,name.Length);Marshal.Copy(name,0,IntPtr.Add(buffer,nameOffset),name.Length);
      Native(SetFileInformationByHandle(h,3,buffer,(uint)length),"rename-refused-no-overwrite");
     } finally {Marshal.FreeHGlobal(buffer);}
     try {
      Exact(h,target);ScopedRecord after=Fresh(destinationRelative,h,true,FileCap);
      if(before.device!=after.device||before.inode!=after.inode||before.size!=after.size||before.sha256!=after.sha256)Refuse("post-move-verification-unresolved");
      return after;
     } catch {throw new InvalidOperationException("scoped:post-move-verification-unresolved");}
    }
   }
  }
  public static void Remove(string root,string relative,ScopedRecord expected,ScopedRecord expectedRoot) {using(Scope s=new Scope(root,expectedRoot)){s.Parents(relative);string p=s.PathOf(relative);using(SafeFileHandle h=Open(p,false,true)){ScopedRecord actual=Fresh(relative,h,true,FileCap);Expected(actual,expected);Exact(h,p);Disposition value=new Disposition{DeleteFile=true};Native(SetFileInformationByHandle(h,4,ref value,4),"delete-refused");}uint attr=GetFileAttributesW(p);int error=Marshal.GetLastWin32Error();if(attr!=0xffffffffu||(error!=2&&error!=3))Refuse("post-purge-verification-unresolved");}}
  public static ScopedRecord Mkdir(string root,string relative,ScopedRecord expectedRoot) {using(Scope s=new Scope(root,expectedRoot)){s.Parents(relative);string p=s.PathOf(relative);Native(CreateDirectoryW(p,IntPtr.Zero),"create-directory-refused");using(SafeFileHandle h=Open(p,true,false)){return Fresh(relative,h,false,0);}}}
  public static ScopedRecord Create(string root,string relative,byte[] data,long maximum,ScopedRecord expectedRoot) {
   if(data==null||maximum<0||maximum>67108864||data.LongLength>maximum)Refuse("create-byte-bound");
   using(Scope s=new Scope(root,expectedRoot)) {
    s.Parents(relative);string p=s.PathOf(relative);
    using(PrivateCreation privacy=new PrivateCreation())
    using(SafeFileHandle h=CreateFileW(p,0x80000000u|0x40000000u|0x80u,0,privacy.Attributes,1,0x00200080u,IntPtr.Zero)) {
     if(h.IsInvalid)Refuse("create-new-refused");Exact(h,p);if(Record(relative,h).nlink!=1)Refuse("hardlink");
     privacy.Validate(h); // Actual TokenUser owner and protected DACL, BEFORE bytes.
     int n;Native(WriteFile(h,data,data.Length,out n,IntPtr.Zero)&&n==data.Length,"partial-create-unresolved");
     Native(FlushFileBuffers(h),"create-flush-unresolved");privacy.Validate(h);
     return Fresh(relative,h,true,maximum);
    }
   }
  }
 }
}
