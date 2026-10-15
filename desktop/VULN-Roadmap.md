# VULN — o que ainda não foi implementado

Situação da versão 3.2.1. Os itens abaixo são pendências, não funcionalidades disponíveis nem datas prometidas.

| Área | Existe hoje | Ainda falta |
|---|---|---|
| Scope | Mapa dos hosts e caminhos observados; crawler restrito à mesma origem | Regras globais include/exclude por host, porta e caminho |
| Proxy | HTTP/1.1, interceptação manual de request/response, histórico, HTTPS MITM opcional | Match & Replace, regras automáticas de interceptação por condição, HTTP/2 e HTTP/3 |
| Repeater | Um request editável; abas de leitura Params/Headers; corpo, headers e resposta raw; JSON com cores | Múltiplos requests/abas de trabalho, grupos, histórico por aba e edição estruturada de query/cookies/JSON |
| Sessões | Cookies e Authorization podem ser editados manualmente no request | Cookie jar automático, macros de login, renovação de tokens e regras por origem |
| Intruder | Quatro modos com listas, URL encoding, limite, intervalo e parada | Geradores de payloads, pipelines de transformação, grep-match/extract e pools de concorrência; execução atual é serial |
| Scanner | Crawl GET de até 50 páginas; checks de cabeçalhos/cookies e reflexão opcional | Crawl com JavaScript/autenticação, catálogo amplo de checks, confirmação de exploração e DSL própria de regras |
| WebSockets | Cliente direto ws/wss, texto e registro de tamanhos binários recebidos | Histórico de frames capturados pelo proxy, edição/interceptação de frames, envio binário e reconexão automática |
| Comparer | Diferenças por posição de linha | Alinhamento de linhas e diff por bytes |
| Decoder | URL/form, Base64 e Hex | Pipeline de transformações, gzip/deflate, parser de JWT e verificação de assinatura |
| Sequencer | Coleta por regex e estatística descritiva | Bateria estatística avançada; o resultado atual não comprova imprevisibilidade criptográfica |
| Organização | Histórico, mapa e tabela de achados | Organizer com notas, tags, coleções e filtros persistentes |
| Navegador | Nenhum navegador embutido | Integração de navegador, instrumentação DOM e análise de fluxos JavaScript |
| Callbacks externos | Não disponível | Serviço DNS/HTTP de callbacks, correlação e expiração de eventos |
| TLS | CA local, PKCS#12 e validação upstream | Cliente mTLS; fluxos com pinning não são suportados |
| Extensões | API Java VulnExtension e exemplo de JAR | Sandbox, instalação/atualização assistida e runtime de linguagens de script |
| Projetos | Salvar e abrir manualmente histórico, rascunhos e achados | Autosave, recuperação após falha, importação de outros formatos e persistência completa de todas as preferências/estado das ferramentas |

Prioridade técnica sugerida: Scope → Match & Replace → edição estruturada → abas/histórico do Repeater → gestão de sessões. Depois, ampliar Scanner, WebSockets e organização de evidências.

Os testes atuais verificam os fluxos implementados com serviços locais; não representam paridade com uma suíte completa de testes de segurança nem validação de todos os cenários de rede reais.
