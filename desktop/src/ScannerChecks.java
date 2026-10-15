import java.net.*;
import java.util.*;
import java.util.regex.*;

final class ScannerChecks {
    record Check(String severity,String title,Pattern pattern){}
    static List<Check> compile(String script){List<Check> checks=new ArrayList<>();for(String line:script.split("\\R")){if(line.isBlank()||line.startsWith("#"))continue;String[] p=line.split("\\t",3);if(p.length!=3||!Set.of("Info","Low","Medium","High").contains(p[0])||p[2].length()>512)throw new IllegalArgumentException("Check: severity<TAB>title<TAB>response regex (max 512 chars)");checks.add(new Check(p[0],p[1],Pattern.compile(p[2],Pattern.DOTALL)));}return checks;}
    static List<WorkbenchCore.Finding> inspect(URI uri,VulnApp.Reply reply,List<Check> custom){List<WorkbenchCore.Finding> out=new ArrayList<>(WorkbenchCore.passive(uri,reply));Map<String,List<String>> h=WorkbenchCore.headers(reply);String body=WorkbenchCore.body(reply),url=uri.toString();
        if(h.getOrDefault("access-control-allow-origin",List.of()).contains("*")&&h.getOrDefault("access-control-allow-credentials",List.of()).stream().anyMatch("true"::equalsIgnoreCase))out.add(new WorkbenchCore.Finding("Low","CORS wildcard with credentials",url,"Both headers are present. Browsers reject this combination for credentialed reads; assess configuration.","Observed configuration"));
        if(h.containsKey("server")||h.containsKey("x-powered-by"))out.add(new WorkbenchCore.Finding("Info","Technology header disclosed",url,"Server: "+h.getOrDefault("server",List.of())+"; X-Powered-By: "+h.getOrDefault("x-powered-by",List.of()),"Observed"));
        if(uri.getScheme().equals("https")&&Pattern.compile("(?i)(?:src|action)\\s*=\\s*[\"']http://").matcher(body).find())out.add(new WorkbenchCore.Finding("Medium","Insecure resource or form target",url,"HTTPS document contains an http:// resource/form attribute.","Review DOM context"));
        if(h.getOrDefault("content-security-policy",List.of()).stream().anyMatch(s->s.contains("'unsafe-eval'")))out.add(new WorkbenchCore.Finding("Low","CSP permits unsafe-eval",url,"unsafe-eval found in CSP.","Observed configuration"));
        Matcher secret=Pattern.compile("-----BEGIN (?:RSA |EC )?PRIVATE KEY-----").matcher(body);if(secret.find())out.add(new WorkbenchCore.Finding("High","Private-key marker in response",url,"Private-key PEM marker detected; key contents intentionally omitted.","Review exposed content"));
        if(Pattern.compile("(?is)<title>Index of /|<h1>Index of /").matcher(body).find())out.add(new WorkbenchCore.Finding("Low","Directory listing pattern",url,"Index of / heading found.","Pattern; review required"));
        if(reply.code()==500)out.add(new WorkbenchCore.Finding("Info","Internal server error",url,"HTTP 500 response observed; does not establish a vulnerability.","Observed"));
        String raw=WorkbenchCore.raw(reply);for(Check check:custom){Matcher m=check.pattern.matcher(raw);if(m.find())out.add(new WorkbenchCore.Finding(check.severity,check.title,url,"Matched response text: "+m.group().substring(0,Math.min(m.group().length(),512)),"Custom rule pattern; review required"));}return out;
    }
}
