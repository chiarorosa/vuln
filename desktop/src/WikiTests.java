import java.util.*;
import javax.swing.text.html.*;
import javax.swing.text.html.parser.*;
import java.io.*;

final class WikiTests {
    static void run()throws Exception {
        Set<String> ids=new HashSet<>();
        for(var article:WikiContent.ALL){
            if(!ids.add(article.id()))throw new AssertionError("Duplicate Wiki id: "+article.id());
            if(article.purpose().isBlank()||article.steps().isBlank()||article.expected().isBlank()||article.example().isBlank()||article.limits().isBlank())throw new AssertionError("Incomplete Wiki article "+article.id());
            new ParserDelegator().parse(new StringReader(article.html()),new HTMLEditorKit.ParserCallback(){
                public void handleStartTag(javax.swing.text.html.HTML.Tag tag,javax.swing.text.MutableAttributeSet attrs,int position){if(tag==javax.swing.text.html.HTML.Tag.A){Object href=attrs.getAttribute(javax.swing.text.html.HTML.Attribute.HREF);if(href==null||!href.toString().startsWith("wiki:")||WikiContent.ALL.stream().noneMatch(a->a.id().equals(href.toString().substring(5))))throw new AssertionError("Broken or external Wiki link "+href);}}
            },true);
        }
        DesktopTests.check(ids.containsAll(List.of("Dashboard","Target","Proxy","Repeater","Decoder","Logger","Intruder","Scanner","Sequencer","Comparer","TLS","WebSockets","Extensions")),"Wiki covers all 13 native tools with instructions and expected results");
        DesktopTests.check(WikiContent.search("CERTIFICACAO ausente").isEmpty()&&WikiContent.search("certificado").stream().anyMatch(a->a.id().equals("TLS"))&&WikiContent.search("interceptacao").stream().anyMatch(a->a.id().equals("Proxy")),"Wiki search ignores accents and case, and handles no matches");
        DesktopTests.check(WikiContent.search("Cluster bomb").stream().anyMatch(a->a.id().equals("Modes")),"Wiki search combines terms across original function names");
        DesktopTests.check(WikiContent.escape("<script>&\"'").equals("&lt;script&gt;&amp;&quot;&#39;"),"Wiki examples escape HTML instead of executing supplied markup");
        DesktopTests.check(ids.size()==WikiContent.ALL.size(),"Wiki article identifiers are unique and internal links resolve offline");
    }
}
