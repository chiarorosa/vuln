import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import javax.swing.*;
import javax.swing.border.*;
import javax.swing.event.*;
import javax.swing.table.*;
import javax.swing.tree.*;

/** Independent native desktop workbench. Native Java/Swing application. */
public class VulnApp extends JFrame {
    static final java.nio.charset.Charset WIRE = StandardCharsets.ISO_8859_1;
    static final Color BG = VulnTheme.CANVAS, PANEL = VulnTheme.PANEL, INK = VulnTheme.TEXT, ACCENT = VulnTheme.ACCENT;
    static final int MAX_BODY = 10 * 1024 * 1024;
    static final String SAMPLE = "GET /hello?name=desktop HTTP/1.1\r\nHost: 127.0.0.1:8091\r\nAccept: application/json\r\n\r\n";
    final ExecutorService workers = Executors.newCachedThreadPool(r -> {Thread t = new Thread(r, "vuln-worker"); t.setDaemon(true); return t;});
    final List<Exchange> entries = new ArrayList<>();
    final JTabbedPane tools = new JTabbedPane();
    final JLabel status = new JLabel("Ready — nenhuma conexão iniciada"), counters = new JLabel();
    final JTextArea logs = area(false), interceptRequest = area(true), historyRequest = area(false), historyResponse = area(false);
    final JTextArea repeaterRequest = area(true), repeaterResponse = area(false), decoderInput = area(true), decoderOutput = area(false);
    final JTextField repeaterUrl = new JTextField("http://127.0.0.1:8091/hello?name=desktop");
    final JCheckBox intercept = new JCheckBox("Intercept is off");
    final JLabel listener = new JLabel("Stopped"), pendingLabel = new JLabel("Nenhuma requisição pendente");
    final JButton forward = new JButton("Forward"), drop = new JButton("Drop"), send = new JButton("Send"), proxyToggle = new JButton("Start proxy");
    final JSpinner port = new JSpinner(new SpinnerNumberModel(8081, 1024, 65535, 1));
    final DefaultTableModel historyModel = model("#", "Host", "Method", "Path", "Status", "Bytes", "ms", "Source");
    final JTable history = new JTable(historyModel);
    final DefaultMutableTreeNode root = new DefaultMutableTreeNode("Observed targets");
    final DefaultTreeModel targetModel = new DefaultTreeModel(root);
    final JTree targetTree = new JTree(targetModel);
    final ArrayDeque<Pending> pending = new ArrayDeque<>();
    final AtomicBoolean interceptEnabled = new AtomicBoolean(false);
    final ProxyEngine proxy;
    final AdvancedTools advanced;
    WikiWindow wiki; RequestWorkbench repeaterView; WorkspaceTools workspace;
    void showWiki(){if(wiki==null)wiki=new WikiWindow(this);wiki.showTopic(tools.getTitleAt(tools.getSelectedIndex()));}
    Pending current;
    com.sun.net.httpserver.HttpServer demoServer;
    int demoPort;

    record Exchange(int id, String method, String url, int code, byte[] request, byte[] response, long millis, String source) {}
    static class Pending {
        final byte[] bytes;
        final URI origin;
        final CompletableFuture<byte[]> decision = new CompletableFuture<>();
        Pending(byte[] bytes) {this(bytes,null);}
        Pending(byte[] bytes,URI origin) {this.bytes = bytes;this.origin=origin;}
    }
    record Packet(String method, String target, String protocol, LinkedHashMap<String,String> headers, byte[] body) {
        String header(String name) {return headers.entrySet().stream().filter(e -> e.getKey().equalsIgnoreCase(name)).map(Map.Entry::getValue).findFirst().orElse("");}
        URI uri(String base) {
            URI targetUri = URI.create(target);
            if (base != null && !base.isBlank()) {
                URI origin = checked(URI.create(base));
                String route = targetUri.isAbsolute() ? (targetUri.getRawPath().isEmpty()?"/":targetUri.getRawPath())+(targetUri.getRawQuery()==null?"":"?"+targetUri.getRawQuery()) : target;
                return checked(origin.resolve(route));
            }
            if (targetUri.isAbsolute()) return checked(targetUri);
            if (header("Host").isBlank()) throw new IllegalArgumentException("Host header obrigatório");
            return checked(URI.create("http://" + header("Host") + (target.startsWith("/") ? target : "/" + target)));
        }
        static URI checked(URI uri) {
            if (uri.getHost() == null || !("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))) throw new IllegalArgumentException("Use uma URL http:// ou https:// válida");
            if (uri.getRawUserInfo() != null) throw new IllegalArgumentException("Coloque credenciais explicitamente no header Authorization");
            return uri;
        }
    }
    record Reply(int code, byte[] raw, int bodySize,Packet sent,String transport) {Reply(int code,byte[] raw,int bodySize){this(code,raw,bodySize,null,"HTTP/1.1");}}
    static volatile NetworkPolicy network;

    public VulnApp() {
        super("VULN · Network Security Workspace");
        proxy = new ProxyEngine(workers, bytes -> {
            if (!interceptEnabled.get() || (network!=null&&!network.intercept(bytes))) return bytes;
            Pending item = new Pending(bytes,activeOrigin());
            SwingUtilities.invokeLater(() -> {if(!interceptEnabled.get()){item.decision.complete(bytes);return;}if(pending.size()>=100){item.decision.complete(null);return;}pending.add(item); showPending();});
            try {return item.decision.get(120, TimeUnit.SECONDS);}
            catch (Exception ex) {SwingUtilities.invokeLater(() -> {pending.remove(item); if (current == item) current = null; showPending();}); return null;}
        }, (packet,url,reply,elapsed) -> SwingUtilities.invokeLater(() -> addExchange(packet,url,reply,elapsed,"Proxy")), this::log);
        advanced=new AdvancedTools(this);
        setDefaultCloseOperation(WindowConstants.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter(){public void windowClosing(WindowEvent e){proxy.stop(); releaseAll();if(workspace!=null)workspace.close();advanced.close(); if(demoServer!=null) demoServer.stop(0); workers.shutdownNow(); dispose();}});
        Rectangle screen=GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();setSize(Math.min(1450,screen.width-32),Math.min(930,screen.height-32));setMinimumSize(new Dimension(Math.min(1180,screen.width-32),Math.min(760,screen.height-32)));setLocationByPlatform(true);setIconImages(List.of(VulnTheme.icon(32),VulnTheme.icon(64),VulnTheme.icon(128)));
        tools.addTab("Dashboard", dashboard()); tools.addTab("Target", targets()); tools.addTab("Proxy", proxyPanel()); tools.addTab("Repeater", repeaterPanel()); tools.addTab("Decoder", decoderPanel()); tools.addTab("Logger", loggerPanel());
        advanced.install(tools); workspace=new WorkspaceTools(this);
        JMenuBar menu = new JMenuBar(); JMenu project = new JMenu("Project"); JMenuItem export = new JMenuItem("Export session JSON…"); export.addActionListener(e -> export()); project.add(export); JMenuItem exit = new JMenuItem("Exit"); exit.addActionListener(e -> dispatchEvent(new WindowEvent(this,WindowEvent.WINDOW_CLOSING))); project.add(exit); menu.add(project);
        JMenuItem saveProject=new JMenuItem("Save project…");saveProject.addActionListener(e->advanced.saveProject());project.insert(saveProject,0);JMenuItem openProject=new JMenuItem("Open project…");openProject.addActionListener(e->advanced.openProject());project.insert(openProject,0);
        JMenu help = new JMenu("Help");JMenuItem wikiItem=new JMenuItem("Wiki em Português Brasil");wikiItem.setAccelerator(KeyStroke.getKeyStroke("F1"));wikiItem.addActionListener(e->showWiki());help.add(wikiItem); JMenuItem about = new JMenuItem("About / limites"); about.addActionListener(e -> JOptionPane.showMessageDialog(this,"VULN 3.2.1 — implementação independente em Swing.\nConsulte a Wiki (F1) para instruções, exemplos e limites de cada ferramenta.\nExtensões usam a API Java própria do VULN.","VULN",JOptionPane.INFORMATION_MESSAGE)); help.add(about); menu.add(help); setJMenuBar(menu);
        forward.addActionListener(e -> resolveCurrent(interceptRequest.getText().getBytes(WIRE))); drop.addActionListener(e -> resolveCurrent(null));
        intercept.addActionListener(e -> {interceptEnabled.set(intercept.isSelected()); intercept.setText(intercept.isSelected()?"Intercept is on":"Intercept is off"); if (!intercept.isSelected()) releaseAll();});
        proxyToggle.addActionListener(e -> toggleProxy());
        history.getSelectionModel().addListSelectionListener(e -> {if(!e.getValueIsAdjusting()) showHistory();});
        setContentPane(new VulnShell(this)); tools.setSelectedIndex(3);
        updateCounts(); showPending();
    }
    static DefaultTableModel model(String... columns) {return new DefaultTableModel(columns,0){public boolean isCellEditable(int row,int column){return false;}};}
    static JTextArea area(boolean edit) {JTextArea text = new JTextArea(); text.setEditable(edit); text.setFont(new Font("Consolas",Font.PLAIN,13)); text.setTabSize(4); text.setBackground(PANEL); text.setForeground(INK); text.setCaretColor(ACCENT); text.setMargin(new Insets(14,14,14,14)); return text;}
    static JPanel page() {JPanel p=new JPanel(new BorderLayout(12,12)); p.setBorder(new EmptyBorder(16,18,16,18)); return p;}
    static JPanel bar(Component... items) {JPanel p=new JPanel(new VulnTheme.ToolbarLayout()); for(Component item:items)p.add(item); return p;}
    static JButton button(String text, Runnable action) {JButton b=new JButton(text); b.addActionListener(e -> action.run()); return b;}
    static JScrollPane titled(String label,Component component) {JScrollPane p=new JScrollPane(component); p.setBorder(BorderFactory.createTitledBorder(label)); return p;}
    static JSplitPane split(int direction, Component left, Component right, double ratio) {JSplitPane p=new JSplitPane(direction,left,right);p.setResizeWeight(ratio);p.setContinuousLayout(true);p.setBorder(null);p.addHierarchyListener(e->{if((e.getChangeFlags()&HierarchyEvent.SHOWING_CHANGED)!=0&&p.isShowing()&&p.getClientProperty("initialDivider")==null){p.putClientProperty("initialDivider",true);SwingUtilities.invokeLater(()->p.setDividerLocation(ratio));}});return p;}
    JPanel dashboard() {
        JPanel p=page(); JPanel top=new JPanel(new GridLayout(0,1,0,10)); JLabel heading=new JLabel("Laboratório HTTP desktop"); heading.setFont(heading.getFont().deriveFont(Font.BOLD,27));top.add(heading);top.add(new JLabel("Inspecione requisições, controle o encaminhamento e repita mensagens com alterações.")); top.add(counters);p.add(top,BorderLayout.NORTH);
        JTextArea notes=area(false);notes.setLineWrap(true);notes.setWrapStyleWord(true);notes.setText("COMEÇAR\n\n1. Inicie o servidor de teste local pelo botão abaixo.\n2. Em Proxy, clique Start proxy e habilite Intercept.\n3. Clique Testar pelo proxy. A requisição fica pausada.\n4. Edite o caminho e clique Forward. Veja o resultado em HTTP history.\n5. Selecione a linha e envie para Repeater, Intruder ou Comparer.\n\nFERRAMENTAS\n\nScanner: análise passiva e crawl limitado à origem, com probes opcionais.\nIntruder: quatro modos de payload, controle de quantidade, intervalo e resultados.\nTLS: CA local, exportação pública e MITM opcional de requests/responses HTTPS.\nSequencer: coleta e estatística descritiva de tokens. Decoder: URL/Base64/hex.\nComparer: comparação de mensagens. WebSockets: cliente com registro de mensagens.\nExtensions: API Java independente. Project: salvar e reabrir sessão local.\n\nProxy em 127.0.0.1:8081 (porta editável); configure manualmente o cliente. TLS MITM exige confiança manual na CA. Nenhuma alteração de proxy ou confiança do Windows é feita automaticamente.\n\nCatálogo de verificações limitado. Consulte a Wiki para o comportamento e os limites de cada ferramenta.");p.add(titled("Workflow",notes),BorderLayout.CENTER);
        p.add(bar(button("Iniciar servidor de teste local",this::startDemo),button("Abrir Proxy",()->tools.setSelectedIndex(2)),button("Abrir Repeater",()->tools.setSelectedIndex(3))),BorderLayout.SOUTH);return p;
    }
    JPanel targets() {JPanel p=page();p.add(new JLabel("Site map — hosts e caminhos efetivamente observados nesta sessão"),BorderLayout.NORTH);p.add(new JScrollPane(targetTree));return p;}
    JPanel proxyPanel() {
        JPanel p=page(); JTabbedPane sub=new JTabbedPane(); JPanel pause=page();
        pause.add(bar(proxyToggle,new JLabel("127.0.0.1 :"),port,listener,intercept,advanced.interceptResponses),BorderLayout.NORTH);
        JPanel inner=new JPanel(new BorderLayout(8,8)); inner.add(bar(forward,drop,button("Send to Repeater",()->{if(current!=null) copyToRepeater(interceptRequest.getText(),current.origin==null?null:current.origin.toString());}),button("Testar pelo proxy",this::demoViaProxy)),BorderLayout.NORTH); inner.add(titled("Intercepted message · request / response · raw ISO-8859-1",interceptRequest)); inner.add(pendingLabel,BorderLayout.SOUTH); pause.add(inner);
        sub.addTab("Intercept",pause);
        JPanel hist=page(); JTextField filter=new JTextField(28); filter.getDocument().addDocumentListener(new DocumentListener(){public void insertUpdate(DocumentEvent e){apply();}public void removeUpdate(DocumentEvent e){apply();}public void changedUpdate(DocumentEvent e){apply();}void apply(){TableRowSorter<?> s=(TableRowSorter<?>)history.getRowSorter();s.setRowFilter(filter.getText().isBlank()?null:RowFilter.regexFilter("(?i)"+java.util.regex.Pattern.quote(filter.getText()),1,2,3,7));}});
        hist.add(bar(new JLabel("Filter"),filter,button("Send to Repeater",this::historyToRepeater),button("Send to Intruder",()->advanced.historyIntruder()),button("Compare response",()->advanced.historyCompare()),button("Export JSON…",this::export)),BorderLayout.NORTH);
        history.setAutoCreateRowSorter(true);history.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);history.setRowHeight(27);
        hist.add(split(JSplitPane.VERTICAL_SPLIT,new JScrollPane(history),split(JSplitPane.HORIZONTAL_SPLIT,titled("Request",historyRequest),titled("Response",historyResponse),.5),.45));sub.addTab("HTTP history",hist);p.add(sub);return p;
    }
    JPanel repeaterPanel() {return repeaterView=new RequestWorkbench(this);}
    JPanel decoderPanel() {
        JPanel p=page();JComboBox<String> codec=new JComboBox<>(new String[]{"URL","Base64","Hex"});
        p.add(bar(codec,button("Encode",()->convert(codec.getSelectedItem().toString(),true)),button("Decode",()->convert(codec.getSelectedItem().toString(),false))),BorderLayout.NORTH);p.add(split(JSplitPane.VERTICAL_SPLIT,titled("Input · UTF-8",decoderInput),titled("Output",decoderOutput),.5));return p;
    }
    JPanel loggerPanel() {JPanel p=page();p.add(bar(button("Export session JSON…",this::export),new JLabel("Eventos da aplicação · histórico de mensagens em Proxy → HTTP history")),BorderLayout.NORTH);p.add(titled("Event log",logs));return p;}
    void updateCounts() {counters.setText("Messages: "+entries.size()+"   •   Hosts: "+entries.stream().map(e->URI.create(e.url).getHost()).distinct().count()+"   •   Pending: "+(pending.size()+(current==null?0:1)));}
    void log(String message) {SwingUtilities.invokeLater(()->{logs.append(LocalTime.now().format(DateTimeFormatter.ofPattern("HH:mm:ss"))+"  "+message+"\n");status.setText(message);});}
    void addExchange(Packet packet, URI uri, Reply reply, long elapsed, String source) {
        if(reply.sent()!=null)packet=reply.sent(); Exchange e=new Exchange(entries.size()+1,packet.method,uri.toString(),reply.code,serialize(packet),reply.raw,elapsed,source);entries.add(e);historyModel.addRow(new Object[]{e.id,uri.getAuthority(),e.method,uri.getRawPath()+(uri.getRawQuery()==null?"":"?"+uri.getRawQuery()),e.code,reply.bodySize,elapsed,source});
        DefaultMutableTreeNode host=null;for(int i=0;i<root.getChildCount();i++){DefaultMutableTreeNode n=(DefaultMutableTreeNode)root.getChildAt(i);if(n.toString().equals(uri.getAuthority()))host=n;}
        if(host==null){host=new DefaultMutableTreeNode(uri.getAuthority());root.add(host);}String path=uri.getRawPath()+(uri.getRawQuery()==null?"":"?"+uri.getRawQuery());boolean exists=false;for(int i=0;i<host.getChildCount();i++)if(host.getChildAt(i).toString().equals(path))exists=true;if(!exists)host.add(new DefaultMutableTreeNode(path));targetModel.reload();for(int i=0;i<targetTree.getRowCount();i++)targetTree.expandRow(i);updateCounts();log(source+" "+packet.method+" "+uri+" → "+reply.code+" ("+elapsed+" ms)");
        advanced.inspect(e,reply);if(workspace!=null&&workspace.scriptsOn.isSelected())workspace.runScript(e);
    }
    Exchange selected() {int row=history.getSelectedRow();return row<0?null:entries.get(history.convertRowIndexToModel(row));}
    void showHistory() {Exchange e=selected();if(e!=null){historyRequest.setText(new String(e.request,WIRE));historyResponse.setText(new String(e.response,WIRE));historyRequest.setCaretPosition(0);historyResponse.setCaretPosition(0);}}
    void historyToRepeater() {Exchange e=selected();if(e==null){log("Selecione uma mensagem no histórico.");return;}if(e.method.equals("CONNECT")){log("CONNECT é um túnel TLS; selecione uma mensagem HTTP ou edite uma no Repeater.");return;}copyToRepeater(new String(e.request,WIRE),e.url);}
    void copyToRepeater(String raw,String url) {try{Packet packet=parse(raw.getBytes(WIRE));repeaterUrl.setText(url==null?packet.uri(null).toString():url);repeaterRequest.setText(raw);repeaterResponse.setText("");tools.setSelectedIndex(3);}catch(Exception ex){error(ex);}}
    URI activeOrigin(){return proxy.context.get();}
    void showPending() {Pending previous=current;if(current==null)current=pending.poll();if(previous!=current||current==null)interceptRequest.setText(current==null?"":new String(current.bytes,WIRE));interceptRequest.setEditable(current!=null);forward.setEnabled(current!=null);drop.setEnabled(current!=null);pendingLabel.setText(current==null?"Nenhuma mensagem pendente":"Paused "+(new String(current.bytes,WIRE).startsWith("HTTP/")?"RESPONSE":"REQUEST")+" · "+(pending.size()+1)+" aguardando · timeout de 120 s");updateCounts();}
    void resolveCurrent(byte[] edited) {if(current!=null){current.decision.complete(edited);current=null;showPending();}}
    void releaseAll() {if(current!=null){current.decision.complete(interceptRequest.getText().getBytes(WIRE));current=null;}while(!pending.isEmpty()){Pending p=pending.poll();p.decision.complete(p.bytes);}showPending();}
    void toggleProxy() {if(proxy.running()){interceptEnabled.set(false);intercept.setSelected(false);intercept.setText("Intercept is off");if(current!=null){current.decision.complete(null);current=null;}while(!pending.isEmpty())pending.poll().decision.complete(null);showPending();proxy.stop();proxyToggle.setText("Start proxy");port.setEnabled(true);listener.setText("Stopped");}else try{proxy.start(((Number)port.getValue()).intValue());proxyToggle.setText("Stop proxy");port.setEnabled(false);listener.setText("Listening");}catch(Exception ex){error(ex);}}
    void sendRepeater() {
        if(workspace!=null){workspace.repeater.send();return;}
        final String raw=repeaterRequest.getText(),url=repeaterUrl.getText();send.setEnabled(false);repeaterResponse.setText("Sending…");
        workers.submit(()->{try{Packet packet=parse(raw.getBytes(WIRE));URI uri=packet.uri(url);long t=System.nanoTime();Reply reply=perform(packet,uri);long ms=TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-t);SwingUtilities.invokeLater(()->{repeaterResponse.setText(new String(reply.raw,WIRE));repeaterResponse.setCaretPosition(0);repeaterView.received(ms,reply.bodySize());addExchange(packet,uri,reply,ms,"Repeater");});}catch(Exception ex){SwingUtilities.invokeLater(()->{repeaterResponse.setText("Request failed: "+ex.getMessage());error(ex);});}finally{SwingUtilities.invokeLater(()->send.setEnabled(true));}});
    }
    void convert(String kind,boolean encode) {try{String input=decoderInput.getText();String out=switch(kind){case "URL"->encode?URLEncoder.encode(input,StandardCharsets.UTF_8):URLDecoder.decode(input,StandardCharsets.UTF_8);case "Base64"->encode?Base64.getEncoder().encodeToString(input.getBytes(StandardCharsets.UTF_8)):new String(Base64.getDecoder().decode(input.trim()),StandardCharsets.UTF_8);default->encode?HexFormat.of().formatHex(input.getBytes(StandardCharsets.UTF_8)):new String(HexFormat.of().parseHex(input.replaceAll("\\s+","")),StandardCharsets.UTF_8);};decoderOutput.setText(out);log(kind+" "+(encode?"encode":"decode")+" concluído");}catch(Exception ex){error(ex);}}
    void error(Exception ex){log("ERROR: "+ex.getClass().getSimpleName()+": "+ex.getMessage());}
    void startDemo() {if(demoServer!=null){log("Servidor de teste em http://127.0.0.1:"+demoPort);return;}try{demoServer=demo(0);demoPort=demoServer.getAddress().getPort();repeaterUrl.setText("http://127.0.0.1:"+demoPort+"/hello?name=desktop");repeaterRequest.setText("GET /hello?name=desktop HTTP/1.1\r\nHost: 127.0.0.1:"+demoPort+"\r\nAccept: application/json\r\n\r\n");advanced.demoReady(demoPort);log("Servidor de teste HTTP iniciado em 127.0.0.1:"+demoPort);}catch(Exception ex){error(ex);}}
    void demoViaProxy() {if(!proxy.running()){log("Inicie o proxy primeiro.");return;}startDemo();if(demoServer==null)return;int proxyPort=((Number)port.getValue()).intValue();int targetPort=demoPort;workers.submit(()->{try(HttpClient client=HttpClient.newBuilder().proxy(ProxySelector.of(new InetSocketAddress("127.0.0.1",proxyPort))).connectTimeout(Duration.ofSeconds(5)).build()){client.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+targetPort+"/hello?name=desktop")).timeout(Duration.ofSeconds(125)).GET().build(),HttpResponse.BodyHandlers.discarding());log("Cliente de teste recebeu a resposta do proxy.");}catch(Exception ex){error(ex);}});}
    void export() {JFileChooser chooser=new JFileChooser();chooser.setSelectedFile(new File("vuln-session.json"));if(chooser.showSaveDialog(this)!=JFileChooser.APPROVE_OPTION)return;Path path=chooser.getSelectedFile().toPath();if(Files.exists(path)&&JOptionPane.showConfirmDialog(this,"Substituir "+path.getFileName()+"?","Export",JOptionPane.YES_NO_OPTION)!=JOptionPane.YES_OPTION)return;try{StringBuilder b=new StringBuilder("[\n");for(int i=0;i<entries.size();i++){Exchange e=entries.get(i);if(i>0)b.append(",\n");b.append("{\"id\":").append(e.id).append(",\"method\":").append(json(e.method)).append(",\"url\":").append(json(e.url)).append(",\"status\":").append(e.code).append(",\"source\":").append(json(e.source)).append(",\"requestBase64\":").append(json(Base64.getEncoder().encodeToString(e.request))).append(",\"responseBase64\":").append(json(Base64.getEncoder().encodeToString(e.response))).append("}");}Files.writeString(path,b.append("\n]\n").toString());log("Exported "+entries.size()+" messages → "+path);}catch(Exception ex){error(ex);}}
    static String json(String s) {StringBuilder b=new StringBuilder("\"");for(char c:s.toCharArray()){switch(c){case '"'->b.append("\\\"");case '\\'->b.append("\\\\");case '\n'->b.append("\\n");case '\r'->b.append("\\r");case '\t'->b.append("\\t");default->{if(c<32)b.append(String.format("\\u%04x",(int)c));else b.append(c);}}}return b.append('"').toString();}
    static byte[] serialize(Packet p) {ByteArrayOutputStream out=new ByteArrayOutputStream();out.writeBytes((p.method+" "+p.target+" "+p.protocol+"\r\n").getBytes(WIRE));p.headers.forEach((k,v)->out.writeBytes((k+": "+v+"\r\n").getBytes(WIRE)));out.writeBytes("\r\n".getBytes(WIRE));out.writeBytes(p.body);return out.toByteArray();}
    static Packet parse(byte[] bytes) throws IOException {return parse(bytes,false);}
    static Packet parse(byte[] bytes,boolean framingOnly) throws IOException {
        String all=new String(bytes,WIRE);int at=all.indexOf("\r\n\r\n"),separator=4;if(at<0){at=all.indexOf("\n\n");separator=2;}if(at<0)throw new IOException("Termine os headers com uma linha vazia");String[] lines=all.substring(0,at).replace("\r\n","\n").split("\n");String[] first=lines[0].split(" ",3);if(first.length!=3||!first[0].matches("[A-Z]+")||!first[2].matches("HTTP/1\\.[01]"))throw new IOException("Linha inicial inválida; use METHOD /path HTTP/1.1");LinkedHashMap<String,String> headers=new LinkedHashMap<>();for(int i=1;i<lines.length;i++){int colon=lines[i].indexOf(':');if(colon<=0)throw new IOException("Header inválido: "+lines[i]);String name=lines[i].substring(0,colon).trim(),value=lines[i].substring(colon+1).trim();if(headers.keySet().stream().anyMatch(k->k.equalsIgnoreCase(name)))throw new IOException("Headers duplicados não são suportados: "+name);headers.put(name,value);}
        if(at>65536)throw new IOException("Headers excedem 64 KiB");byte[] body=Arrays.copyOfRange(bytes,at+separator,bytes.length);if(body.length>MAX_BODY)throw new IOException("Body excede 10 MiB");Packet packet=new Packet(first[0],first[1],first[2],headers,body);if(!framingOnly&&!packet.header("Transfer-Encoding").isEmpty()){if(!packet.header("Transfer-Encoding").equalsIgnoreCase("chunked")||!packet.header("Content-Length").isBlank())throw new IOException("Enquadramento Transfer-Encoding inválido");body=readChunks(new ByteArrayInputStream(body));headers.keySet().removeIf(k->Set.of("transfer-encoding","trailer").contains(k.toLowerCase(Locale.ROOT)));headers.put("Content-Length",String.valueOf(body.length));return new Packet(first[0],first[1],first[2],headers,body);}return packet;
    }
    static byte[] readRequest(InputStream input) throws IOException {return readRequest(input,null);}
    static byte[] readRequest(InputStream input,OutputStream interim) throws IOException {
        ByteArrayOutputStream head=new ByteArrayOutputStream();int state=0;while(state<4){int c=input.read();if(c<0)throw new EOFException("Cliente fechou a conexão");head.write(c);state=switch(state){case 0->c==13?1:0;case 1->c==10?2:0;case 2->c==13?3:0;default->c==10?4:0;};if(head.size()>65536)throw new IOException("Headers excedem 64 KiB");}
        Packet p=parse(head.toByteArray(),true);if(!p.header("Expect").isEmpty()){if(!p.header("Expect").equalsIgnoreCase("100-continue")||interim==null)throw new IOException("Expect não suportado nesta operação");interim.write("HTTP/1.1 100 Continue\r\n\r\n".getBytes(WIRE));interim.flush();}
        String transfer=p.header("Transfer-Encoding"),length=p.header("Content-Length");if(!transfer.isBlank()&&!length.isBlank())throw new IOException("Content-Length com Transfer-Encoding é ambíguo");byte[] body;
        if(!transfer.isBlank()){if(!transfer.equalsIgnoreCase("chunked"))throw new IOException("Transfer-Encoding não suportado");body=readChunks(input);}else{int n=0;try{if(!length.isBlank())n=Integer.parseInt(length);}catch(NumberFormatException e){throw new IOException("Content-Length inválido");}if(n<0||n>MAX_BODY)throw new IOException("Content-Length fora do limite de 10 MiB");body=input.readNBytes(n);if(body.length!=n)throw new EOFException("Body incompleto");}
        if(transfer.isBlank()&&p.header("Expect").isBlank()){head.writeBytes(body);return head.toByteArray();}LinkedHashMap<String,String> normalized=new LinkedHashMap<>(p.headers);normalized.keySet().removeIf(k->Set.of("transfer-encoding","content-length","expect","trailer").contains(k.toLowerCase(Locale.ROOT)));normalized.put("Content-Length",String.valueOf(body.length));return serialize(new Packet(p.method,p.target,p.protocol,normalized,body));
    }
    static String wireLine(InputStream input) throws IOException {ByteArrayOutputStream out=new ByteArrayOutputStream();while(out.size()<8192){int c=input.read();if(c<0)throw new EOFException("Linha HTTP incompleta");if(c==13){if(input.read()!=10)throw new IOException("CRLF inválido");return out.toString(WIRE);}out.write(c);}throw new IOException("Linha HTTP excede 8 KiB");}
    static byte[] readChunks(InputStream input) throws IOException {ByteArrayOutputStream out=new ByteArrayOutputStream();while(true){String line=wireLine(input);long size;try{size=Long.parseLong(line.split(";",2)[0].trim(),16);}catch(NumberFormatException ex){throw new IOException("Chunk size inválido");}if(size<0||size>MAX_BODY-out.size())throw new IOException("Body excede 10 MiB");if(size==0){int trailerBytes=0;while(true){String trailer=wireLine(input);trailerBytes+=trailer.length();if(trailerBytes>65536)throw new IOException("Trailers excedem 64 KiB");if(trailer.isEmpty())return out.toByteArray();}}byte[] chunk=input.readNBytes((int)size);if(chunk.length!=size)throw new EOFException("Chunk incompleto");out.writeBytes(chunk);if(input.read()!=13||input.read()!=10)throw new IOException("Chunk sem CRLF");}}
    static Reply perform(Packet packet,URI uri) throws Exception {return perform(packet,uri,null);}
    static Reply perform(Packet packet,URI uri,javax.net.ssl.SSLContext trust) throws Exception {NetworkPolicy policy=network;return policy==null?performDirect(packet,uri,trust,HttpClient.Version.HTTP_1_1):policy.send(packet,uri,trust);}
    static Reply performDirect(Packet packet,URI uri,javax.net.ssl.SSLContext trust,HttpClient.Version version) throws Exception {
        HttpRequest.Builder request=HttpRequest.newBuilder(uri).version(version).timeout(Duration.ofSeconds(30));
        Set<String> blocked=new HashSet<>(Set.of("host","content-length","connection","proxy-connection","keep-alive","transfer-encoding","upgrade","expect","proxy-authorization","proxy-authenticate","te","trailer"));for(String name:packet.header("Connection").split(","))blocked.add(name.trim().toLowerCase(Locale.ROOT));
        packet.headers.forEach((name,value)->{if(!blocked.contains(name.toLowerCase(Locale.ROOT)))request.header(name,value);});request.method(packet.method,packet.body.length==0?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofByteArray(packet.body));
        HttpClient.Builder clientBuilder=HttpClient.newBuilder().proxy(new ProxySelector(){public List<Proxy> select(URI u){return List.of(Proxy.NO_PROXY);}public void connectFailed(URI u,SocketAddress a,IOException ex){}}).connectTimeout(Duration.ofSeconds(10)).followRedirects(HttpClient.Redirect.NEVER);if(trust!=null)clientBuilder.sslContext(trust);
        try(HttpClient client=clientBuilder.build()) {
            HttpResponse<InputStream> response=client.send(request.build(),HttpResponse.BodyHandlers.ofInputStream());byte[] body;try(InputStream stream=response.body()){body=stream.readNBytes(MAX_BODY+1);}if(body.length>MAX_BODY)throw new IOException("Resposta excede 10 MiB");
            ByteArrayOutputStream out=new ByteArrayOutputStream();out.writeBytes(("HTTP/1.1 "+response.statusCode()+" "+reason(response.statusCode())+"\r\n").getBytes(WIRE));response.headers().map().forEach((name,values)->{if(!Set.of("content-length","transfer-encoding","connection","keep-alive").contains(name.toLowerCase(Locale.ROOT)))for(String value:values)out.writeBytes((name+": "+value+"\r\n").getBytes(WIRE));});out.writeBytes(("Content-Length: "+body.length+"\r\nConnection: close\r\n\r\n").getBytes(WIRE));out.writeBytes(body);return new Reply(response.statusCode(),out.toByteArray(),body.length,packet,response.version()==HttpClient.Version.HTTP_2?"HTTP/2":"HTTP/1.1");
        }
    }
    static String reason(int code) {return switch(code){case 200->"OK";case 201->"Created";case 204->"No Content";case 301->"Moved Permanently";case 302->"Found";case 304->"Not Modified";case 400->"Bad Request";case 401->"Unauthorized";case 403->"Forbidden";case 404->"Not Found";case 500->"Internal Server Error";case 502->"Bad Gateway";default->"Response";};}
    interface Capture {void accept(Packet p,URI u,Reply r,long ms);}
    interface Interceptor {byte[] accept(byte[] raw) throws Exception;}
    interface Sender {Reply send(Packet packet,URI uri) throws Exception;}
    static class ProxyEngine {
        final ExecutorService workers;final Interceptor interceptor;final Capture capture;final Consumer<String> log;
        final Set<Socket> sockets=ConcurrentHashMap.newKeySet(); volatile ServerSocket server;
        final ThreadLocal<URI> context=new ThreadLocal<>();
        volatile TlsAuthority authority;volatile boolean mitm;volatile Sender sender=VulnApp::perform;volatile Interceptor responseInterceptor=bytes->bytes;
        ProxyEngine(ExecutorService workers,Interceptor interceptor,Capture capture,Consumer<String> log){this.workers=workers;this.interceptor=interceptor;this.capture=capture;this.log=log;}
        boolean running(){return server!=null&&!server.isClosed();}
        synchronized void start(int port) throws IOException {if(running())return;ServerSocket bound=new ServerSocket();try{bound.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),port));}catch(IOException ex){bound.close();throw ex;}server=bound;log.accept("Proxy listening on 127.0.0.1:"+bound.getLocalPort());workers.submit(()->{while(!bound.isClosed())try{Socket client=bound.accept();sockets.add(client);workers.submit(()->handle(client));}catch(IOException ex){if(!bound.isClosed())log.accept("Accept failed: "+ex.getMessage());}});}
        synchronized void stop(){ServerSocket bound=server;server=null;if(bound!=null)try{bound.close();}catch(IOException ignored){}for(Socket socket:sockets)try{socket.close();}catch(IOException ignored){}sockets.clear();log.accept("Proxy stopped");}
        void handle(Socket client){try(client){try{client.setSoTimeout(150000);byte[] raw=readRequest(client.getInputStream(),client.getOutputStream());Packet packet=parse(raw);if(packet.method.equals("CONNECT")){tunnel(client,packet);return;}serve(client,raw,null);}catch(Exception ex){log.accept("Proxy error: "+ex.getMessage());try{writeError(client,502,ex.getMessage());}catch(Exception ignored){}}}catch(IOException ignored){}finally{sockets.remove(client);}}
        void serve(Socket client,byte[] raw,URI origin) throws Exception {context.set(origin);try{byte[] edited=interceptor.accept(raw);if(edited==null){writeError(client,403,"Request dropped or interception timed out");return;}Packet packet=parse(edited);URI uri=packet.uri(origin==null?null:origin.toString());if(origin==null&&!"http".equalsIgnoreCase(uri.getScheme()))throw new IOException("Use CONNECT para HTTPS no proxy");if(packet.header("Upgrade").equalsIgnoreCase("websocket")){WsProxy.handle(client,packet,uri,workers);return;}long start=System.nanoTime();Reply original=sender.send(packet,uri);byte[] changed=responseInterceptor.accept(original.raw);if(changed==null){writeError(client,403,"Response dropped or interception timed out");return;}Reply reply=Arrays.equals(changed,original.raw)?original:reframe(changed);if(reply.sent()==null&&original.sent()!=null)reply=new Reply(reply.code(),reply.raw(),reply.bodySize(),original.sent(),original.transport());client.getOutputStream().write(reply.raw);client.getOutputStream().flush();capture.accept(packet,uri,reply,TimeUnit.NANOSECONDS.toMillis(System.nanoTime()-start));}finally{context.remove();}}
        void tunnel(Socket client,Packet packet) throws Exception {
            URI uri=URI.create("https://"+packet.target);if(uri.getHost()==null||uri.getPort()<1||uri.getRawUserInfo()!=null||!(uri.getRawPath()==null||uri.getRawPath().isEmpty()))throw new IOException("CONNECT requer host:port");
            if(network!=null)network.requireScope(uri); TlsAuthority ca=authority;if(mitm&&ca!=null){client.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(WIRE));client.getOutputStream().flush();try(javax.net.ssl.SSLSocket ssl=(javax.net.ssl.SSLSocket)ca.serverContext(uri.getHost()).getSocketFactory().createSocket(client,uri.getHost(),uri.getPort(),false)){ssl.setUseClientMode(false);ssl.setSoTimeout(150000);javax.net.ssl.SSLParameters params=ssl.getSSLParameters();params.setApplicationProtocols(new String[]{"http/1.1"});ssl.setSSLParameters(params);ssl.startHandshake();log.accept("TLS MITM "+packet.target+" — downstream CA local; upstream validation enabled");try{serve(ssl,readRequest(ssl.getInputStream(),ssl.getOutputStream()),uri);}catch(Exception ex){log.accept("HTTPS upstream error: "+ex.getMessage());writeError(ssl,502,ex.getMessage());}}return;}
            try(Socket remote=new Socket()){sockets.add(remote);remote.connect(new InetSocketAddress(uri.getHost(),uri.getPort()),10000);remote.setSoTimeout(120000);client.getOutputStream().write("HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(WIRE));client.getOutputStream().flush();log.accept("CONNECT "+packet.target+" — TLS tunnel sem descriptografia");capture.accept(packet,uri,new Reply(200,"HTTP/1.1 200 Connection Established\r\n\r\nTLS tunnel: payload não inspecionado.".getBytes(WIRE),0),0);
                Future<?> upstream=workers.submit(()->{try{client.getInputStream().transferTo(remote.getOutputStream());remote.shutdownOutput();}catch(IOException ignored){}});try{remote.getInputStream().transferTo(client.getOutputStream());client.getOutputStream().flush();}finally{upstream.cancel(true);sockets.remove(remote);}
            }
        }
        static void writeError(Socket socket,int code,String message) throws IOException {byte[] body=String.valueOf(message).getBytes(StandardCharsets.UTF_8);socket.getOutputStream().write(("HTTP/1.1 "+code+" "+reason(code)+"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: "+body.length+"\r\nConnection: close\r\n\r\n").getBytes(WIRE));socket.getOutputStream().write(body);}
    }
    static Reply reframe(byte[] raw) throws IOException {String message=new String(raw,WIRE);int at=message.indexOf("\r\n\r\n"),skip=4;if(at<0){at=message.indexOf("\n\n");skip=2;}if(at<0)throw new IOException("Resposta sem separador de headers");String[] lines=message.substring(0,at).replace("\r\n","\n").split("\n");if(!lines[0].matches("HTTP/1\\.[01] [1-5][0-9]{2}.*"))throw new IOException("Status HTTP inválido");int code=Integer.parseInt(lines[0].split(" ")[1]);byte[] body=Arrays.copyOfRange(raw,at+skip,raw.length);if(body.length>MAX_BODY)throw new IOException("Body excede 10 MiB");ByteArrayOutputStream out=new ByteArrayOutputStream();out.writeBytes((lines[0]+"\r\n").getBytes(WIRE));for(int i=1;i<lines.length;i++){int colon=lines[i].indexOf(':');if(colon<=0)throw new IOException("Header inválido");if(!Set.of("content-length","transfer-encoding","connection").contains(lines[i].substring(0,colon).toLowerCase(Locale.ROOT)))out.writeBytes((lines[i]+"\r\n").getBytes(WIRE));}out.writeBytes(("Content-Length: "+body.length+"\r\nConnection: close\r\n\r\n").getBytes(WIRE));out.writeBytes(body);return new Reply(code,out.toByteArray(),body.length);}
    static com.sun.net.httpserver.HttpServer demo(int port) throws IOException {
        com.sun.net.httpserver.HttpServer server=com.sun.net.httpserver.HttpServer.create(new InetSocketAddress("127.0.0.1",port),0);server.createContext("/",exchange->{try{byte[] input=exchange.getRequestBody().readNBytes(MAX_BODY+1);String body="{\n  \"server\": \"VULN local HTTP fixture\",\n  \"method\": "+json(exchange.getRequestMethod())+",\n  \"path\": "+json(exchange.getRequestURI().toString())+",\n  \"body\": "+json(new String(input,StandardCharsets.UTF_8))+"\n}";byte[] response=body.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type","application/json; charset=utf-8");exchange.getResponseHeaders().set("Set-Cookie","session="+UUID.randomUUID()+"; HttpOnly; SameSite=Lax");exchange.sendResponseHeaders(200,response.length);exchange.getResponseBody().write(response);}finally{exchange.close();}});server.createContext("/lab",exchange->{try{String query=String.valueOf(exchange.getRequestURI().getRawQuery());String html="<!doctype html><title>REA test fixture</title><h1>Local scanner fixture</h1><p>"+AdvancedTools.html(query)+"</p><a href='/lab/page'>Page</a>";byte[] body=html.getBytes(StandardCharsets.UTF_8);exchange.getResponseHeaders().set("Content-Type","text/html; charset=utf-8");exchange.getResponseHeaders().set("Server","REA-Local-Fixture");exchange.getResponseHeaders().set("Set-Cookie","fixture=value; Path=/lab");exchange.sendResponseHeaders(200,body.length);exchange.getResponseBody().write(body);}finally{exchange.close();}});server.start();return server;
    }
    static void theme() {VulnTheme.setup();}
    public static void main(String[] args) throws Exception {if(args.length>0&&args[0].equals("--self-test")){DesktopTests.run();return;}SwingUtilities.invokeLater(()->{theme();new VulnApp().setVisible(true);});}
}
