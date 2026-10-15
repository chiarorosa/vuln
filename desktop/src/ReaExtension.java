import java.util.List;

/** Independent extension API, loaded only by an explicit user action. */
public interface ReaExtension {
    String name();
    List<Issue> inspect(String method,String url,byte[] request,byte[] response) throws Exception;
    record Issue(String severity,String title,String evidence) {}
}
