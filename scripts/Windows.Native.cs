using System;
using System.IO;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Microsoft.Win32.SafeHandles;
namespace PortableToolkit {
 public sealed class OwnedRecord {
  public string relative_path; public string kind; public long bytes; public long write_ticks; public uint attributes; public uint volume; public string file_id; public string sha256;
 }
 public sealed class CleanupResult { public int files; public int directories; public long logical_bytes; }
 public static class OwnedNative {
  [StructLayout(LayoutKind.Sequential)] struct Info { public uint Attributes; public System.Runtime.InteropServices.ComTypes.FILETIME Creation,Access,Write; public uint Volume,SizeHigh,SizeLow,Links,IdHigh,IdLow; }
  [StructLayout(LayoutKind.Sequential)] struct Disposition { public uint Flags; }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern SafeFileHandle CreateFileW(string p,uint access,uint share,IntPtr security,uint creation,uint flags,IntPtr template);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(SafeFileHandle h,out Info info);
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern uint GetFinalPathNameByHandleW(SafeFileHandle h,StringBuilder p,uint n,uint flags);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool ReadFile(SafeFileHandle h,byte[] b,int count,out int read,IntPtr overlap);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFilePointerEx(SafeFileHandle h,long offset,out long position,uint method);
  [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetFileInformationByHandle(SafeFileHandle h,int cls,ref Disposition value,uint size);
  const uint Dir=0x10,Reparse=0x400;
  sealed class Node { public string Path; public OwnedRecord Record; public SafeFileHandle Handle; }
  static string Full(string p) { return Path.GetFullPath(p).TrimEnd(Path.DirectorySeparatorChar); }
  static string Key(string p) { return p.Replace('\\','/'); }
  static void Refuse(string stage) { throw new InvalidOperationException("Owned cleanup refused: "+stage); }
  static Info Metadata(SafeFileHandle h) { Info i;if(!GetFileInformationByHandle(h,out i))Refuse("metadata");return i; }
  static void ExactPath(SafeFileHandle h,string p) { StringBuilder b=new StringBuilder(32768);uint n=GetFinalPathNameByHandleW(h,b,(uint)b.Capacity,0);if(n==0||n>=b.Capacity)Refuse("canonical-path");string s=b.ToString();if(s.StartsWith("\\\\?\\UNC\\",StringComparison.OrdinalIgnoreCase))s="\\\\"+s.Substring(8);else if(s.StartsWith("\\\\?\\"))s=s.Substring(4);if(!String.Equals(Full(s),Full(p),StringComparison.OrdinalIgnoreCase))Refuse("exact-path-mismatch"); }
  static SafeFileHandle Open(string p,bool directory,bool delete) { uint access=0x80u|(directory?1u:1u)|(delete?0x10000u:0u);SafeFileHandle h=CreateFileW(p,access,directory?3u:1u,IntPtr.Zero,3,0x02200000,IntPtr.Zero);if(h.IsInvalid){h.Dispose();Refuse("access-or-sharing");}try{ExactPath(h,p);Info i=Metadata(h);if((i.Attributes&Reparse)!=0)Refuse("reparse");if(((i.Attributes&Dir)!=0)!=directory)Refuse("type");if(!directory&&i.Links!=1)Refuse("hardlink");return h;}catch{h.Dispose();throw;} }
  static string Hash(SafeFileHandle h) { long pos;if(!SetFilePointerEx(h,0,out pos,0))Refuse("seek");using(SHA256 sha=SHA256.Create()){byte[] b=new byte[65536];int n;while(true){if(!ReadFile(h,b,b.Length,out n,IntPtr.Zero))Refuse("hash-read");if(n==0)break;sha.TransformBlock(b,0,n,b,0);}sha.TransformFinalBlock(new byte[0],0,0);return BitConverter.ToString(sha.Hash).Replace("-","").ToLowerInvariant();} }
  static OwnedRecord Record(string rel,SafeFileHandle h,bool directory) { Info i=Metadata(h);return new OwnedRecord{relative_path=Key(rel),kind=directory?"directory":"file",bytes=directory?0:((long)i.SizeHigh<<32)|i.SizeLow,write_ticks=((long)i.Write.dwHighDateTime<<32)|(uint)i.Write.dwLowDateTime,attributes=i.Attributes,volume=i.Volume,file_id=i.IdHigh.ToString("x8")+i.IdLow.ToString("x8"),sha256=directory?null:Hash(h)}; }
  static bool Same(OwnedRecord a,OwnedRecord b) { return a.relative_path==b.relative_path&&a.kind==b.kind&&a.bytes==b.bytes&&a.write_ticks==b.write_ticks&&a.attributes==b.attributes&&a.volume==b.volume&&a.file_id==b.file_id&&a.sha256==b.sha256; }
  sealed class Batch:IDisposable {
   readonly List<Node> nodes=new List<Node>();readonly List<SafeFileHandle> ancestors=new List<SafeFileHandle>();readonly Dictionary<string,string> allowed;readonly HashSet<string> selected;readonly string root;bool disposed;
   public Batch(string work,string run,string[] entries,string[] targets,OwnedRecord[] expected) {
    root=Full(run);work=Full(work);if(!String.Equals(Path.GetDirectoryName(root),work,StringComparison.OrdinalIgnoreCase)||!System.Text.RegularExpressions.Regex.IsMatch(Path.GetFileName(root),"\\Arun-[a-f0-9]{32}\\z"))Refuse("run-boundary");
    allowed=new Dictionary<string,string>(StringComparer.OrdinalIgnoreCase);foreach(string s in entries){if(s.Length<2||s[1]!='|'||(s[0]!='D'&&s[0]!='F'))Refuse("allowlist");string rel=s.Substring(2);if(rel.StartsWith("/")||rel.Contains("\\")||rel.Split('/').Any(x=>x==".."||x=="."))Refuse("relative-path");if(allowed.ContainsKey(rel))Refuse("duplicate-path");allowed.Add(rel,s[0]=='D'?"directory":"file");}if(!allowed.ContainsKey("")||allowed[""]!="directory")Refuse("missing-root");
    selected=new HashSet<string>(targets,StringComparer.OrdinalIgnoreCase);if(selected.Any(x=>!allowed.ContainsKey(x)))Refuse("unowned-target");
    try{string cur=Path.GetPathRoot(root);foreach(string part in root.Substring(cur.Length).Split(Path.DirectorySeparatorChar)){if(cur!=Path.GetPathRoot(root))ancestors.Add(Open(cur,true,false));cur=Path.Combine(cur,part);if(String.Equals(cur,root,StringComparison.OrdinalIgnoreCase))break;}Walk(root,"");if(nodes.Count!=allowed.Count)Refuse("missing-owned-entry");if(expected!=null){if(expected.Length!=nodes.Count)Refuse("stale-membership");Dictionary<string,OwnedRecord> map=expected.ToDictionary(x=>x.relative_path,StringComparer.OrdinalIgnoreCase);foreach(Node n in nodes){OwnedRecord e;if(!map.TryGetValue(n.Record.relative_path,out e)||!Same(e,n.Record))Refuse("stale-content-or-identity");}}Validate();}catch{Dispose();throw;}
   }
   void Walk(string path,string rel) { if(nodes.Count>=20000)Refuse("node-limit");string kind;if(!allowed.TryGetValue(Key(rel),out kind))Refuse("unknown-entry");bool dir=kind=="directory";SafeFileHandle h=Open(path,dir,selected.Contains(Key(rel)));Node node=new Node{Path=path,Handle=h,Record=Record(rel,h,dir)};nodes.Add(node);if(dir){foreach(string child in Directory.EnumerateFileSystemEntries(path).OrderBy(x=>x,StringComparer.Ordinal)){string leaf=Path.GetFileName(child);Walk(child,rel.Length==0?leaf:Path.Combine(rel,leaf));}} }
   void Validate() { foreach(Node n in nodes){ExactPath(n.Handle,n.Path);if(!Same(n.Record,Record(n.Record.relative_path,n.Handle,n.Record.kind=="directory")))Refuse("changed-after-pin");if(n.Record.kind=="directory"){string[] live=Directory.EnumerateFileSystemEntries(n.Path).Select(x=>Key(n.Record.relative_path.Length==0?Path.GetFileName(x):Path.Combine(n.Record.relative_path,Path.GetFileName(x)))).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray();string[] old=nodes.Where(x=>String.Equals(Path.GetDirectoryName(x.Path),n.Path,StringComparison.OrdinalIgnoreCase)).Select(x=>x.Record.relative_path).OrderBy(x=>x,StringComparer.OrdinalIgnoreCase).ToArray();if(!live.SequenceEqual(old,StringComparer.OrdinalIgnoreCase))Refuse("membership-drift");}} }
   public OwnedRecord[] Snapshot() {return nodes.Select(x=>x.Record).OrderBy(x=>x.relative_path,StringComparer.Ordinal).ToArray();}
   public CleanupResult Delete() { CleanupResult result=new CleanupResult();try{Validate();foreach(Node n in nodes.Where(x=>selected.Contains(x.Record.relative_path)).OrderByDescending(x=>x.Record.relative_path.Count(c=>c=='/')).ThenByDescending(x=>x.Record.relative_path,StringComparer.Ordinal)){ExactPath(n.Handle,n.Path);Disposition d=new Disposition{Flags=0x13};if(!SetFileInformationByHandle(n.Handle,21,ref d,4))Refuse("unlink-failed-"+Marshal.GetLastWin32Error());if(n.Record.kind=="directory")result.directories++;else{result.files++;result.logical_bytes+=n.Record.bytes;}n.Handle.Dispose();}return result;}catch(Exception e){e.Data["deleted_files"]=result.files;e.Data["deleted_directories"]=result.directories;e.Data["deleted_logical_bytes"]=result.logical_bytes;throw;} }
   public void Dispose(){if(disposed)return;disposed=true;for(int i=nodes.Count-1;i>=0;i--)nodes[i].Handle.Dispose();for(int i=ancestors.Count-1;i>=0;i--)ancestors[i].Dispose();}
  }
  public static byte[] ReadPublicFile(string sourceRoot,string relative) {
   if(String.IsNullOrEmpty(relative)||relative.StartsWith("/")||relative.Contains("\\")||relative.Contains(":")||relative.Split('/').Any(x=>x=="."||x==".."||x.Length==0||String.Equals(x,"work",StringComparison.OrdinalIgnoreCase)||String.Equals(x,".git",StringComparison.OrdinalIgnoreCase)))Refuse("public-relative-path");
   string root=Full(sourceRoot),file=Full(Path.Combine(root,relative.Replace('/',Path.DirectorySeparatorChar)));if(!file.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))Refuse("public-boundary");List<SafeFileHandle> held=new List<SafeFileHandle>();
   try{string parent=Path.GetDirectoryName(file),cur=Path.GetPathRoot(parent);foreach(string part in parent.Substring(cur.Length).Split(Path.DirectorySeparatorChar)){cur=Path.Combine(cur,part);held.Add(Open(cur,true,false));}using(SafeFileHandle h=Open(file,false,false)){Info before=Metadata(h);long length=((long)before.SizeHigh<<32)|before.SizeLow;if(length>4000000)Refuse("public-size");using(MemoryStream m=new MemoryStream()){byte[] b=new byte[65536];int n;while(true){if(!ReadFile(h,b,b.Length,out n,IntPtr.Zero))Refuse("public-read");if(n==0)break;m.Write(b,0,n);}Info after=Metadata(h);ExactPath(h,file);if(before.Volume!=after.Volume||before.IdHigh!=after.IdHigh||before.IdLow!=after.IdLow||before.SizeHigh!=after.SizeHigh||before.SizeLow!=after.SizeLow||before.Write.dwHighDateTime!=after.Write.dwHighDateTime||before.Write.dwLowDateTime!=after.Write.dwLowDateTime||before.Attributes!=after.Attributes)Refuse("public-drift");return m.ToArray();}}}finally{for(int i=held.Count-1;i>=0;i--)held[i].Dispose();}
  }
  public static OwnedRecord InspectOwnedFile(string sourceRoot,string relative) {
   if(String.IsNullOrEmpty(relative)||relative.StartsWith("/")||relative.Contains("\\")||relative.Contains(":")||relative.Split('/').Any(x=>x=="."||x==".."||x.Length==0))Refuse("owned-relative-path");
   string root=Full(sourceRoot),file=Full(Path.Combine(root,relative.Replace('/',Path.DirectorySeparatorChar)));
   if(!file.StartsWith(root+Path.DirectorySeparatorChar,StringComparison.OrdinalIgnoreCase))Refuse("owned-boundary");
   List<SafeFileHandle> held=new List<SafeFileHandle>();
   try {
    string parent=Path.GetDirectoryName(file),cur=Path.GetPathRoot(parent);
    foreach(string part in parent.Substring(cur.Length).Split(Path.DirectorySeparatorChar)){cur=Path.Combine(cur,part);held.Add(Open(cur,true,false));}
    using(SafeFileHandle handle=Open(file,false,false)) {
     OwnedRecord before=Record(relative,handle,false),after=Record(relative,handle,false);
     ExactPath(handle,file);if(!Same(before,after))Refuse("owned-file-drift");return before;
    }
   } finally {for(int i=held.Count-1;i>=0;i--)held[i].Dispose();}
  }
  public static OwnedRecord[] Capture(string work,string run,string[] entries,string[] targets){using(Batch b=new Batch(work,run,entries,targets,null))return b.Snapshot();}
  public static CleanupResult Delete(string work,string run,string[] entries,string[] targets,OwnedRecord[] expected){using(Batch b=new Batch(work,run,entries,targets,expected))return b.Delete();}
 }
}
