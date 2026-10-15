import java.awt.*;
import javax.swing.*;
import javax.swing.event.*;

/** Modeless native Swing help, with no browser, network or WebView dependency. */
final class WikiWindow extends JDialog {
    final JTextField search=new JTextField();
    final DefaultListModel<WikiContent.Article> model=new DefaultListModel<>();
    final JList<WikiContent.Article> topics=new JList<>(model);
    final JEditorPane page=new JEditorPane("text/html","");
    final JLabel count=new JLabel();
    final JButton open=new JButton("Abrir ferramenta");
    final VulnApp app;
    WikiWindow(VulnApp app){super(app,"VULN · Wiki em Português do Brasil",false);this.app=app;setDefaultCloseOperation(HIDE_ON_CLOSE);
        JPanel body=new JPanel(new BorderLayout(16,16));body.setBorder(BorderFactory.createEmptyBorder(18,18,18,18));setContentPane(body);
        JPanel head=new JPanel(new BorderLayout(12,8));head.add(new JLabel("Wiki · Guias, exemplos e resultados esperados"),BorderLayout.WEST);head.add(new JLabel("F1 · ajuda contextual    Ctrl F · buscar    Esc · fechar"),BorderLayout.EAST);body.add(head,BorderLayout.NORTH);
        JPanel sidebar=new JPanel(new BorderLayout(0,10));search.putClientProperty("JTextField.placeholderText","Buscar função, controle ou dúvida…");search.getAccessibleContext().setAccessibleName("Buscar na Wiki em português");sidebar.add(search,BorderLayout.NORTH);topics.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);topics.setFixedCellHeight(38);topics.setVisibleRowCount(16);sidebar.add(new JScrollPane(topics));sidebar.add(count,BorderLayout.SOUTH);sidebar.setPreferredSize(new Dimension(315,500));
        topics.setBackground(VulnTheme.PANEL);topics.setForeground(VulnTheme.TEXT);topics.setSelectionBackground(new Color(0x343128));topics.setSelectionForeground(VulnTheme.ACCENT);
        page.setEditable(false);page.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES,true);page.getAccessibleContext().setAccessibleName("Artigo da Wiki");JScrollPane scroll=new JScrollPane(page);scroll.getVerticalScrollBar().setUnitIncrement(20);JSplitPane split=new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,sidebar,scroll);split.setResizeWeight(.28);split.setBorder(null);body.add(split);
        JPanel foot=new JPanel(new BorderLayout());foot.add(new JLabel("Documentação local · VULN 3.2.1 · Conteúdo original em pt-BR"));foot.add(open,BorderLayout.EAST);body.add(foot,BorderLayout.SOUTH);
        topics.addListSelectionListener(e->{if(!e.getValueIsAdjusting())render();});search.getDocument().addDocumentListener(new DocumentListener(){public void insertUpdate(DocumentEvent e){filter();}public void removeUpdate(DocumentEvent e){filter();}public void changedUpdate(DocumentEvent e){filter();}});
        page.addHyperlinkListener(e->{if(e.getEventType()==HyperlinkEvent.EventType.ACTIVATED&&e.getDescription().startsWith("wiki:"))select(e.getDescription().substring(5));});open.addActionListener(e->{var a=topics.getSelectedValue();if(a!=null){app.advanced.select(a.tool());app.toFront();}});
        VulnShell.bind(getRootPane(),"control F","wiki-search",()->{search.requestFocusInWindow();search.selectAll();});VulnShell.bind(getRootPane(),"ESCAPE","wiki-close",()->setVisible(false));
        Rectangle bounds=GraphicsEnvironment.getLocalGraphicsEnvironment().getMaximumWindowBounds();setSize(Math.min(1160,bounds.width-40),Math.min(800,bounds.height-40));setMinimumSize(new Dimension(Math.min(850,bounds.width-40),Math.min(540,bounds.height-40)));setLocationRelativeTo(app);filter();
    }
    void filter(){String previous=topics.getSelectedValue()==null?null:topics.getSelectedValue().id();model.clear();WikiContent.search(search.getText()).forEach(model::addElement);count.setText(model.size()+" de "+WikiContent.ALL.size()+" artigos");if(!model.isEmpty()){int index=0;for(int i=0;i<model.size();i++)if(model.get(i).id().equals(previous))index=i;topics.setSelectedIndex(index);}else render();}
    void render(){var a=topics.getSelectedValue();open.setEnabled(a!=null);page.setText(a==null?"<html><body style='color:#d4d4d4;background:#191919;font-family:Segoe UI;padding:24px'><h1>Nenhum artigo encontrado</h1><p>Tente outro termo: certificado, payload, sessão ou interceptação.</p></body></html>":a.html());page.setCaretPosition(0);}
    void select(String id){search.setText("");topics.setSelectedValue(WikiContent.byId(id),true);}
    void showTopic(String id){select(id);setVisible(true);toFront();topics.requestFocusInWindow();}
}
