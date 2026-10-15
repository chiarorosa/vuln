import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;

public class DesktopTests {
    static int checks;
    static void check(boolean ok,String name){if(!ok)throw new AssertionError(name);checks++;System.out.println("PASS "+name);}
    static byte[] raw(String s){return s.getBytes(VulnApp.WIRE);}
    static String proxyRequest(int port,String request) throws Exception {try(Socket socket=new Socket("127.0.0.1",port)){socket.setSoTimeout(10000);socket.getOutputStream().write(raw(request));return new String(socket.getInputStream().readAllBytes(),VulnApp.WIRE);}}
    static void run() throws Exception {
        var origin=VulnApp.demo(0);int targetPort=origin.getAddress().getPort();String authority="127.0.0.1:"+targetPort;
        ExecutorService workers=Executors.newCachedThreadPool();AtomicReference<VulnApp.Interceptor> action=new AtomicReference<>(bytes->bytes);BlockingQueue<String> captured=new LinkedBlockingQueue<>();
        var proxy=new VulnApp.ProxyEngine(workers,bytes->action.get().accept(bytes),(p,u,r,ms)->captured.add(p.method()+" "+u+" "+r.code()),s->{});
        try {
            byte[] body={0,13,10,(byte)255,42};ByteArrayOutputStream binary=new ByteArrayOutputStream();binary.writeBytes(raw("POST /echo HTTP/1.1\r\nHost: "+authority+"\r\nContent-Length: 5\r\n\r\n"));binary.writeBytes(body);
            check(Arrays.equals(VulnApp.parse(binary.toByteArray()).body(),body),"parser preserves binary body and CRLF");
            check(Arrays.equals(VulnApp.readRequest(new ByteArrayInputStream(binary.toByteArray())),binary.toByteArray()),"socket framing preserves body bytes");
            var packet=VulnApp.parse(raw("GET /hello?name=repeater HTTP/1.1\r\nHost: "+authority+"\r\n\r\n"));var reply=VulnApp.perform(packet,packet.uri(null));check(reply.code()==200&&new String(reply.raw(),VulnApp.WIRE).contains("name=repeater"),"Repeater reaches actual HTTP server");
            var post=VulnApp.parse(raw("POST /echo HTTP/1.1\r\nHost: "+authority+"\r\nContent-Type: text/plain\r\n\r\nhello desktop"));var postReply=VulnApp.perform(post,post.uri(null));check(new String(postReply.raw(),VulnApp.WIRE).contains("hello desktop"),"POST body reaches origin");
            check(packet.uri("http://localhost:"+targetPort+"/").getHost().equals("localhost"),"Repeater destination origin is editable");
            proxy.start(0);int proxyPort=proxy.server.getLocalPort();String request="GET http://"+authority+"/hello?name=proxy HTTP/1.1\r\nHost: "+authority+"\r\n\r\n";
            String response=proxyRequest(proxyPort,request);check(response.startsWith("HTTP/1.1 200")&&response.contains("name=proxy"),"explicit HTTP proxy forwards real response");check(captured.poll(3,TimeUnit.SECONDS)!=null,"forwarded request reaches history capture");
            CountDownLatch paused=new CountDownLatch(1);CompletableFuture<byte[]> decision=new CompletableFuture<>();action.set(bytes->{paused.countDown();return decision.get(5,TimeUnit.SECONDS);});Future<String> waiting=workers.submit(()->proxyRequest(proxyPort,request));check(paused.await(3,TimeUnit.SECONDS)&&!waiting.isDone(),"interception pauses network forwarding");decision.complete(raw(request.replace("name=proxy","name=edited")));check(waiting.get(5,TimeUnit.SECONDS).contains("name=edited"),"Forward sends edited HTTP request");
            action.set(bytes->null);check(proxyRequest(proxyPort,request).startsWith("HTTP/1.1 403"),"Drop returns explicit rejection to client");
            action.set(bytes->bytes);check(proxyRequest(proxyPort,"GET / HTTP/1.1\r\nHost: "+authority+"\r\nTransfer-Encoding: gzip\r\n\r\n").startsWith("HTTP/1.1 502"),"unsupported request framing returns HTTP error");
            try(ServerSocket echo=new ServerSocket(0,1,InetAddress.getByName("127.0.0.1"));Socket tunnel=new Socket("127.0.0.1",proxyPort)){
                Future<?> echoTask=workers.submit(()->{try(Socket peer=echo.accept()){peer.getOutputStream().write(peer.getInputStream().readNBytes(4));}catch(IOException ex){throw new UncheckedIOException(ex);}});
                tunnel.setSoTimeout(5000);tunnel.getOutputStream().write(raw("CONNECT 127.0.0.1:"+echo.getLocalPort()+" HTTP/1.1\r\nHost: 127.0.0.1:"+echo.getLocalPort()+"\r\n\r\n"));ByteArrayOutputStream head=new ByteArrayOutputStream();while(!head.toString(VulnApp.WIRE).endsWith("\r\n\r\n")){int b=tunnel.getInputStream().read();if(b<0)throw new EOFException();head.write(b);}check(head.toString(VulnApp.WIRE).contains("200 Connection Established"),"CONNECT opens explicit tunnel");tunnel.getOutputStream().write(raw("PING"));check(new String(tunnel.getInputStream().readNBytes(4),VulnApp.WIRE).equals("PING"),"CONNECT tunnel carries actual bytes bidirectionally");echoTask.get(3,TimeUnit.SECONDS);
            }
            proxy.stop();check(!proxy.running(),"Stop releases listener");
            AdvancedTests.run();
            WikiTests.run();
            WorkspaceTests.run();
            System.out.println("ALL "+checks+" CHECKS PASSED — real loopback networking");
        } finally {proxy.stop();origin.stop(0);workers.shutdownNow();}
    }
}
