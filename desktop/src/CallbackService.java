import java.io.*;
import java.net.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.*;

final class CallbackService implements AutoCloseable {
    record Event(Instant time,String token,String transport,String peer,String evidence){}
    final Map<String,Instant> tokens=new ConcurrentHashMap<>();
    final List<Event> events=new CopyOnWriteArrayList<>();
    final Consumer<Event> sink;
    com.sun.net.httpserver.HttpServer http;DatagramSocket dns;volatile boolean running;
    CallbackService(Consumer<Event> sink){this.sink=sink;}
    String issue(int minutes){if(tokens.size()>10000)tokens.entrySet().removeIf(e->e.getValue().isBefore(Instant.now()));if(tokens.size()>=10000)throw new IllegalStateException("Maximum callback tokens");String token=UUID.randomUUID().toString().replace("-","");tokens.put(token,Instant.now().plusSeconds(minutes*60L));return token;}
    void record(String token,String transport,String peer,String value){Instant expiry=tokens.get(token);if(expiry==null||expiry.isBefore(Instant.now()))return;Event event=new Event(Instant.now(),token,transport,peer,value.substring(0,Math.min(value.length(),4096)));events.add(event);if(events.size()>10000)events.removeFirst();sink.accept(event);}
    synchronized void start(String bind,int httpPort,int dnsPort)throws Exception{if(running)throw new IOException("Callbacks already running");InetAddress address=InetAddress.getByName(bind);http=com.sun.net.httpserver.HttpServer.create(new InetSocketAddress(address,httpPort),32);try{dns=new DatagramSocket(new InetSocketAddress(address,dnsPort));http.createContext("/",exchange->{try{String token=exchange.getRequestURI().getPath().replaceFirst("^/","").split("/")[0];record(token,"HTTP",exchange.getRemoteAddress().toString(),exchange.getRequestMethod()+" "+exchange.getRequestURI());byte[] response="VULN callback received".getBytes(java.nio.charset.StandardCharsets.UTF_8);exchange.sendResponseHeaders(200,response.length);exchange.getResponseBody().write(response);}finally{exchange.close();}});running=true;http.start();Thread thread=new Thread(this::dnsLoop,"vuln-callback-dns");thread.setDaemon(true);thread.start();}catch(Exception ex){http.stop(0);if(dns!=null)dns.close();throw ex;}}
    void dnsLoop(){byte[] buffer=new byte[4096];while(running)try{DatagramPacket datagram=new DatagramPacket(buffer,buffer.length);dns.receive(datagram);byte[] data=Arrays.copyOf(datagram.getData(),datagram.getLength());if(data.length<17||data[4]!=0||data[5]!=1)continue;int p=12;List<String> labels=new ArrayList<>();while(p<data.length){int n=data[p++]&255;if(n==0)break;if(n>63||p+n>data.length)throw new IOException("DNS label");labels.add(new String(data,p,n,java.nio.charset.StandardCharsets.US_ASCII));p+=n;}if(p+4>data.length)continue;String name=String.join(".",labels);if(!labels.isEmpty())record(labels.getFirst(),"DNS",datagram.getSocketAddress().toString(),name);byte[] reply=Arrays.copyOf(data,p+4);reply[2]=(byte)0x81;reply[3]=(byte)0x83;for(int k=6;k<12;k++)reply[k]=0;dns.send(new DatagramPacket(reply,reply.length,datagram.getSocketAddress()));}catch(Exception ex){if(!running)return;}}
    public synchronized void close(){running=false;if(http!=null)http.stop(0);if(dns!=null)dns.close();http=null;dns=null;}
}
