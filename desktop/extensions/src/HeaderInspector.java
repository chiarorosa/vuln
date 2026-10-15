import java.util.List;
import java.nio.charset.StandardCharsets;

/** Minimal independent extension example. No network or file access. */
public class HeaderInspector implements VulnExtension {
    public String name(){return "Example: server header inventory";}
    public List<Issue> inspect(String method,String url,byte[] request,byte[] response){
        String raw=new String(response,StandardCharsets.ISO_8859_1);int at=raw.indexOf("\r\n\r\n");String headers=at<0?raw:raw.substring(0,at);
        return headers.lines().filter(line->line.toLowerCase(java.util.Locale.ROOT).startsWith("server:")).map(line->new Issue("Info","Server header declared",line+" — metadata only, not proof of a vulnerability.")).toList();
    }
}
