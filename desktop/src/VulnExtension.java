import java.util.List;

/** Public VULN inspection extension API. */
public interface VulnExtension {
    String name();
    List<Issue> inspect(String method,String url,byte[] request,byte[] response) throws Exception;
    record Issue(String severity,String title,String evidence) {}
}
