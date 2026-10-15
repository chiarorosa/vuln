# VULN 3.2.1 — Windows desktop

Abra VULN.exe. O runtime Java acompanha a distribuição. No projeto, start.cmd abre desktop/releases/3.2.1/VULN/VULN.exe. Versões anteriores permanecem preservadas.

O visual segue a referência enviada: superfícies grafite, bordas discretas, navegação lateral compacta, abas com marcador amarelo e botão Send amarelo. A tela inicial abre no Repeater; Overview continua na navegação.

## Repeater

O campo URL define a origem. Método, caminho e query vêm da primeira linha de Request. Edite o request raw nessa aba. Params e Headers são visualizações derivadas de leitura; para alterar valores use Request. Clique Send ou Ctrl Enter para enviar.

À direita, Response mostra o corpo; JSON identificado pelo Content-Type ganha indentação e destaque de sintaxe em respostas de até 256 KiB. Headers mostra cabeçalhos e Raw preserva a resposta HTTP completa. O editor Raw é a referência fiel dos bytes apresentados como ISO-8859-1, conforme as versões anteriores. A visualização JSON é textual e não valida nem executa o conteúdo.

Status, tempo em ms e tamanho do corpo em bytes são medidos no envio real. Sem resposta, a tela exibe No response. Não há dados de demonstração simulados no painel.

Para experimentar: abra Overview → Start local test server, volte ao Repeater e envie o request preenchido automaticamente. O servidor usa uma porta local disponível.

## Wiki em pt-BR

F1, botão Wiki · PT-BR ou menu Help. Vinte artigos offline cobrem as treze ferramentas. Ctrl F busca; Esc fecha apenas a Wiki. Os nomes das funções continuam em inglês. O tema da Wiki acompanha o aplicativo.



Extensões usam a API Java própria VulnExtension. Consulte VULN-Roadmap.md para as funcionalidades ainda não implementadas. Wiki, interface e distribuição descrevem somente o VULN.
