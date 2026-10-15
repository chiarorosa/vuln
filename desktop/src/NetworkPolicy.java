import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.*;
import javax.net.ssl.*;

/** One shared policy for all HTTP tools; tests can construct isolated policies. */
final class NetworkPolicy {
    record Rule(boolean response,String expression,String replacement) {}
    record Macro(URI origin,String request,String tokenRegex,String targetHeader) {}
    final List<Rule> rules=new CopyOnWriteArrayList<>();
    final List<Pattern> includes=new CopyOnWriteArrayList<>(),excludes=new CopyOnWriteArrayList<>();
    final CookieManager cookies=new CookieManager(null,CookiePolicy.ACCEPT_ORIGINAL_SERVER);
    final Map<String,String> sessionHeaders=new ConcurrentHashMap<>();
    final Map<String,Macro> macros=new ConcurrentHashMap<>();
    final Map<String,Object> originLocks=new ConcurrentHashMap<>();
    final Map<String,SSLContext> clientCertificates=new ConcurrentHashMap<>();
    volatile boolean enforceScope,cookieJar,matchRules,interceptOnlyMatching;
    volatile Pattern interceptPattern=Pattern.compile(".*",Pattern.DOTALL);
    volatile String protocol="HTTP/1.1";
    volatile Path curl;
    final ThreadLocal<Boolean> inMacro=ThreadLocal.withInitial(()->false);
    static String origin(URI u){return u.getScheme().toLowerCase(Locale.ROOT)+"://"+u.getHost().toLowerCase(Locale.ROOT)+":"+WorkbenchCore.effectivePort(u);}
    boolean allows(URI u){String value=u.toString();return !enforceScope||(excludes.stream().noneMatch(p->p.matcher(value).find())&&(includes.isEmpty()||includes.stream().anyMatch(p->p.matcher(value).find())));}
    void requireScope(URI u)throws IOException{if(!allows(u))throw new IOException("Blocked by Scope: "+u);}
    void configureScope(boolean enabled,String include,String exclude){List<Pattern> a=patterns(include),b=patterns(exclude);includes.clear();includes.addAll(a);excludes.clear();excludes.addAll(b);enforceScope=enabled;}
    static List<Pattern> patterns(String text){return text.lines().filter(s->!s.isBlank()).map(Pattern::compile).toList();}
    String transform(String raw,boolean response){if(!matchRules)return raw;String value=raw;for(Rule rule:rules)if(rule.response==response){value=Pattern.compile(rule.expression,Pattern.DOTALL).matcher(value).replaceAll(rule.replacement);if(value.length()>VulnApp.MAX_BODY+65536)throw new IllegalArgumentException("Rule output exceeds message limit");}return value;}
    boolean intercept(byte[] message){return !interceptOnlyMatching||interceptPattern.matcher(new String(message,VulnApp.WIRE)).find();}
    synchronized void rules(String spec){List<Rule> next=new ArrayList<>();for(String line:spec.split("\\R")){if(line.isBlank()||line.startsWith("#"))continue;String[] fields=line.split("\\t",3);if(fields.length!=3||!Set.of("request","response").contains(fields[0]))throw new IllegalArgumentException("Use request/response<TAB>regex<TAB>replacement");Pattern.compile(fields[1]);next.add(new Rule(fields[0].equals("response"),fields[1],fields[2].replace("\\r","\r").replace("\\n","\n")));}rules.clear();rules.addAll(next);}
    static VulnApp.Packet header(VulnApp.Packet packet,String name,String value){if(!name.matches("[!#$%&'*+.^_`|~0-9A-Za-z-]+")||value.contains("\r")||value.contains("\n"))throw new IllegalArgumentException("Invalid header");LinkedHashMap<String,String> h=new LinkedHashMap<>(packet.headers());h.keySet().removeIf(k->k.equalsIgnoreCase(name));if(!value.isEmpty())h.put(name,value);return new VulnApp.Packet(packet.method(),packet.target(),packet.protocol(),h,packet.body());}
    VulnApp.Reply send(VulnApp.Packet input,URI uri,SSLContext trust)throws Exception{
        requireScope(uri);VulnApp.Packet packet=VulnApp.parse(transform(new String(VulnApp.serialize(input),VulnApp.WIRE),false).getBytes(VulnApp.WIRE));uri=packet.uri(uri.toString());requireScope(uri);String key=origin(uri);
        synchronized(originLocks.computeIfAbsent(key,k->new Object())){
            if(cookieJar){Map<String,List<String>> values=cookies.get(uri,Map.of());String value=String.join("; ",values.getOrDefault("Cookie",List.of()));if(!value.isEmpty()&&packet.header("Cookie").isBlank())packet=header(packet,"Cookie",value);}
            String configured=sessionHeaders.get(key);if(configured!=null){int at=configured.indexOf(':');packet=header(packet,configured.substring(0,at),configured.substring(at+1).strip());}
        }
        VulnApp.Reply reply=direct(packet,uri,trust);
        if((reply.code()==401||reply.code()==403)&&macros.containsKey(key)&&!inMacro.get()){
            synchronized(originLocks.computeIfAbsent(key,k->new Object())){
                inMacro.set(true);try{Macro macro=macros.get(key);var login=VulnApp.parse(macro.request.getBytes(VulnApp.WIRE));URI loginUri=login.uri(macro.origin.toString());requireScope(loginUri);var fresh=direct(login,loginUri,trust);if(cookieJar)cookies.put(macro.origin,WorkbenchCore.headers(fresh));
                    if(!macro.tokenRegex.isBlank()){Matcher found=Pattern.compile(macro.tokenRegex,Pattern.DOTALL).matcher(WorkbenchCore.raw(fresh));if(!found.find()||found.groupCount()<1)throw new IOException("Session macro did not extract capture group 1");String token=found.group(1);packet=header(packet,macro.targetHeader,token);sessionHeaders.put(key,macro.targetHeader+": "+token);}
                    if(cookieJar){String value=String.join("; ",cookies.get(uri,Map.of()).getOrDefault("Cookie",List.of()));if(!value.isEmpty())packet=header(packet,"Cookie",value);}reply=direct(packet,uri,trust);
                }finally{inMacro.set(false);}
            }
        }
        if(cookieJar)cookies.put(uri,WorkbenchCore.headers(reply));String changed=transform(WorkbenchCore.raw(reply),true);if(!changed.equals(WorkbenchCore.raw(reply)))reply=VulnApp.reframe(changed.getBytes(VulnApp.WIRE));
        return new VulnApp.Reply(reply.code(),reply.raw(),reply.bodySize(),packet,reply.transport());
    }
    VulnApp.Reply direct(VulnApp.Packet p,URI u,SSLContext trust)throws Exception{SSLContext tls=trust!=null?trust:clientCertificates.get(origin(u));if(protocol.equals("HTTP/3")){if(tls!=null)throw new IOException("HTTP/3 with custom TLS context is not supported");return curl(p,u);}return VulnApp.performDirect(p,u,tls,protocol.equals("HTTP/2")?HttpClient.Version.HTTP_2:HttpClient.Version.HTTP_1_1);}
    void clientCertificate(URI uri,Path file,char[] password)throws Exception{KeyStore store=KeyStore.getInstance("PKCS12");try(InputStream in=Files.newInputStream(file)){store.load(in,password);}KeyManagerFactory km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());km.init(store,password);SSLContext ctx=SSLContext.getInstance("TLS");ctx.init(km.getKeyManagers(),null,new SecureRandom());clientCertificates.put(origin(uri),ctx);}
    VulnApp.Reply curl(VulnApp.Packet packet,URI uri)throws Exception{
        if(curl==null||!Files.isRegularFile(curl))throw new IOException("HTTP/3 transport unavailable: configure curl with HTTP3 support");if(!uri.getScheme().equals("https"))throw new IOException("HTTP/3 requires https://");
        Path folder=Files.createTempDirectory("vuln-h3-");Path data=folder.resolve("body"),head=folder.resolve("headers"),out=folder.resolve("response"),err=folder.resolve("error");
        try{Files.write(data,packet.body());List<String> args=new ArrayList<>(List.of(curl.toString(),"--disable","--silent","--show-error","--http3-only","--max-time","30","--max-filesize",String.valueOf(VulnApp.MAX_BODY),"--proto","=https","--request",packet.method(),"--dump-header",head.toString(),"--output",out.toString()));for(var h:packet.headers().entrySet())if(!Set.of("host","content-length","connection","transfer-encoding").contains(h.getKey().toLowerCase(Locale.ROOT))){args.add("--header");args.add(h.getKey()+": "+h.getValue());}if(packet.body().length>0){args.add("--data-binary");args.add("@"+data);}args.add("--url");args.add(uri.toString());Process process=new ProcessBuilder(args).redirectError(err.toFile()).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();if(!process.waitFor(35,TimeUnit.SECONDS)){process.destroyForcibly();throw new IOException("HTTP/3 timeout");}if(process.exitValue()!=0)throw new IOException("HTTP/3: "+Files.readString(err));byte[] bytes=Files.readAllBytes(out);if(bytes.length>VulnApp.MAX_BODY)throw new IOException("HTTP/3 body limit");String headers=Files.readString(head,VulnApp.WIRE).replaceFirst("HTTP/3 ","HTTP/1.1 ");ByteArrayOutputStream combined=new ByteArrayOutputStream();combined.write(headers.getBytes(VulnApp.WIRE));combined.write(bytes);return VulnApp.reframe(combined.toByteArray());}finally{for(Path f:List.of(data,head,out,err))Files.deleteIfExists(f);Files.deleteIfExists(folder);}
    }
}
