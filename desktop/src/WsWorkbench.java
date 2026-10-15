import java.awt.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import javax.swing.*;

final class WsWorkbench implements AutoCloseable {
    record Pending(WsProxy.Message message,CompletableFuture<byte[]> decision){}
    final VulnApp app;final JCheckBox intercept=new JCheckBox("Intercept proxy messages"),reconnect=new JCheckBox("Reconnect (up to 3 attempts)");
    final JTextArea edit=VulnApp.area(true);final JLabel status=new JLabel("No paused message");final javax.swing.table.DefaultTableModel rows=VulnApp.model("Direction","Type","Bytes","URL");final List<WsProxy.Message> captured=new ArrayList<>();final ArrayDeque<Pending> queue=new ArrayDeque<>();Pending current;volatile boolean active=true;int retries;
    WsWorkbench(VulnApp app){this.app=app;JTabbedPane tabs=new JTabbedPane();Component direct=app.tools.getComponentAt(11);JPanel client=new JPanel(new BorderLayout());client.add(direct);client.add(VulnApp.bar(reconnect,VulnApp.button("Send Base64 binary",()->{try{var ws=app.advanced.websocket;if(ws==null)throw new IllegalStateException("Connect first");ws.sendBinary(ByteBuffer.wrap(Base64.getDecoder().decode(app.advanced.wsMessage.getText().strip())),true).exceptionally(ex->{app.log(ex.getMessage());return null;});}catch(Exception ex){app.error(ex);}})),BorderLayout.SOUTH);tabs.addTab("Client",client);
        JPanel proxy=VulnApp.page();JTable history=new JTable(rows);history.setAutoCreateRowSorter(true);history.getSelectionModel().addListSelectionListener(e->{int row=history.getSelectedRow();if(row>=0&&current==null){var message=captured.get(history.convertRowIndexToModel(row));edit.setText(display(message));}});proxy.add(VulnApp.bar(intercept,VulnApp.button("Forward edited",()->decide(true)),VulnApp.button("Drop",()->decide(false)),status),BorderLayout.NORTH);proxy.add(VulnApp.split(JSplitPane.VERTICAL_SPLIT,new JScrollPane(history),VulnApp.titled("Message · text UTF-8 / binary Base64 · 120 s decision timeout",edit),.5));tabs.addTab("Proxy frames",proxy);app.tools.setComponentAt(11,tabs);intercept.addActionListener(e->{if(!intercept.isSelected())release();});WsProxy.editor=this::accept;}
    static String display(WsProxy.Message m){return m.opcode()==1?new String(m.payload(),StandardCharsets.UTF_8):Base64.getEncoder().encodeToString(m.payload());}
    byte[] accept(WsProxy.Message m)throws Exception{CompletableFuture<byte[]> decision=new CompletableFuture<>();SwingUtilities.invokeLater(()->{captured.add(m);rows.addRow(new Object[]{m.outbound()?"OUT":"IN",m.opcode()==1?"TEXT":"BINARY",m.payload().length,m.uri()});if(captured.size()>1000){captured.removeFirst();rows.removeRow(0);}if(!intercept.isSelected()||!active)decision.complete(m.payload());else if(queue.size()>=100)decision.complete(null);else{queue.add(new Pending(m,decision));show();}});try{return decision.get(120,TimeUnit.SECONDS);}catch(TimeoutException ex){SwingUtilities.invokeLater(()->{queue.removeIf(p->p.decision==decision);if(current!=null&&current.decision==decision)current=null;show();});return null;}}
    void show(){if(current==null)current=queue.poll();if(current!=null){edit.setText(display(current.message));status.setText((current.message.outbound()?"OUT ":"IN ")+"paused · "+(queue.size()+1));}else status.setText("No paused message");}
    void decide(boolean forward){if(current==null)return;try{byte[] value=forward?(current.message.opcode()==1?edit.getText().getBytes(StandardCharsets.UTF_8):Base64.getDecoder().decode(edit.getText().strip())):null;current.decision.complete(value);current=null;show();}catch(Exception ex){app.error(ex);}}
    void release(){if(current!=null){current.decision.complete(current.message.payload());current=null;}while(!queue.isEmpty()){Pending p=queue.poll();p.decision.complete(p.message.payload());}show();}
    void connected(){retries=0;}
    void disconnected(){if(!active||!reconnect.isSelected()||retries++>=3)return;app.workers.submit(()->{try{Thread.sleep(1500);SwingUtilities.invokeLater(()->{if(active&&reconnect.isSelected()&&app.advanced.websocket==null)app.advanced.connectWS();});}catch(InterruptedException ex){Thread.currentThread().interrupt();}});}
    public void close(){active=false;release();WsProxy.editor=m->m.payload();}
}
