import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;

final class AttackPool {
    static void run(String template,String base,List<List<String>> sets,String mode,int delay,int limit,int concurrency,AtomicBoolean stop,Consumer<WorkbenchCore.AttackResult> sink)throws Exception{
        List<String> requests=WorkbenchCore.payloadRequests(template,sets,mode,limit);ExecutorService pool=Executors.newFixedThreadPool(concurrency);CompletionService<WorkbenchCore.AttackResult> completion=new ExecutorCompletionService<>(pool);AtomicLong slot=new AtomicLong();List<Future<WorkbenchCore.AttackResult>> futures=new ArrayList<>();int next=0,active=0;
        try{while((next<requests.size()||active>0)&&!stop.get()){
            while(active<concurrency&&next<requests.size()&&!stop.get()){int index=next++;String raw=requests.get(index);futures.add(completion.submit(()->{long target=slot.getAndUpdate(value->Math.max(value,System.nanoTime())+TimeUnit.MILLISECONDS.toNanos(delay));long remaining=target-System.nanoTime();if(remaining>0)TimeUnit.NANOSECONDS.sleep(remaining);if(stop.get())throw new CancellationException();VulnApp.Packet packet=null;URI uri=null;long start=System.nanoTime();try{packet=VulnApp.parse(raw.getBytes(VulnApp.WIRE));uri=packet.uri(base);var reply=VulnApp.perform(packet,uri);return new WorkbenchCore.AttackResult(index+1,raw,packet,uri,reply,(System.nanoTime()-start)/1000000,"");}catch(Exception ex){return new WorkbenchCore.AttackResult(index+1,raw,packet,uri,null,(System.nanoTime()-start)/1000000,Objects.toString(ex.getMessage(),ex.getClass().getSimpleName()));}}));active++;}
            Future<WorkbenchCore.AttackResult> result=completion.poll(100,TimeUnit.MILLISECONDS);if(result!=null){active--;try{sink.accept(result.get());}catch(CancellationException ignored){}}
        }}finally{futures.forEach(f->f.cancel(true));pool.shutdownNow();pool.awaitTermination(3,TimeUnit.SECONDS);}
    }
}
