import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

final class ProjectStore {
    record Project(List<VulnApp.Exchange> messages,Map<String,String> settings) {}
    static final int MAGIC=0x52454132,MAX_FILE=256*1024*1024,MAX_MESSAGES=10000;
    static void write(Path path,Project project) throws IOException {
        if(project.messages.size()>MAX_MESSAGES)throw new IOException("Limite de 10000 mensagens por projeto");Path parent=path.toAbsolutePath().getParent();Path temp=Files.createTempFile(parent,".rea-project-",".tmp");
        try{try(DataOutputStream out=new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(temp)))){out.writeInt(MAGIC);out.writeInt(2);out.writeInt(project.settings.size());for(var item:project.settings.entrySet()){text(out,item.getKey());text(out,item.getValue());}out.writeInt(project.messages.size());for(var e:project.messages){text(out,e.method());text(out,e.url());out.writeInt(e.code());bytes(out,e.request());bytes(out,e.response());out.writeLong(e.millis());text(out,e.source());}}if(Files.size(temp)>MAX_FILE)throw new IOException("Projeto excede 256 MiB");Files.move(temp,path,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(temp);}
    }
    static Project read(Path path) throws IOException {
        if(Files.size(path)>MAX_FILE)throw new IOException("Projeto excede 256 MiB");try(DataInputStream in=new DataInputStream(new BufferedInputStream(Files.newInputStream(path)))){if(in.readInt()!=MAGIC)throw new IOException("Formato de projeto inválido");int version=in.readInt();if(version!=1&&version!=2)throw new IOException("Versão de projeto inválida");int n=count(in,256);Map<String,String> settings=new LinkedHashMap<>();for(int i=0;i<n;i++)settings.put(text(in),text(in));int total=count(in,MAX_MESSAGES);List<VulnApp.Exchange> records=new ArrayList<>();long loaded=0;for(int i=0;i<total;i++){String method=text(in),url=text(in);try{VulnApp.Packet.checked(java.net.URI.create(url));}catch(Exception ex){throw new IOException("URL inválida no projeto",ex);}int code=in.readInt();byte[] request=bytes(in,VulnApp.MAX_BODY+65536),response=bytes(in,VulnApp.MAX_BODY+262144);loaded+=request.length+response.length;if(loaded>MAX_FILE)throw new IOException("Projeto excede limite de memória");long elapsed=in.readLong();String source=text(in);VulnApp.parse(request);records.add(new VulnApp.Exchange(i+1,method,url,code,request,response,elapsed,source));}if(in.read()!=-1)throw new IOException("Dados adicionais no projeto");return new Project(records,settings);}
    }
    static int count(DataInputStream in,int max) throws IOException {int n=in.readInt();if(n<0||n>max)throw new IOException("Contagem inválida no projeto");return n;}
    static void text(DataOutputStream out,String value) throws IOException {byte[] data=value.getBytes(StandardCharsets.UTF_8);if(data.length>16*1024*1024)throw new IOException("Campo de texto excede 16 MiB");bytes(out,data);}
    static String text(DataInputStream in) throws IOException {return new String(bytes(in,16*1024*1024),StandardCharsets.UTF_8);}
    static void bytes(DataOutputStream out,byte[] value) throws IOException {out.writeInt(value.length);out.write(value);}
    static byte[] bytes(DataInputStream in,int max) throws IOException {int n=count(in,max);byte[] data=in.readNBytes(n);if(data.length!=n)throw new EOFException("Projeto truncado");return data;}
}
