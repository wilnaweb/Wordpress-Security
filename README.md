
# Guia de Segurança Wordpress
Este guia é um passo a passo simples com o objetivo de aumentar a segurança do Wordpress afim de mitigar possíveis problemas conhecidos.

O ideal que a sua implementação seja total, mas é necessário avaliar cada item individualmente afim de verificar a possibilidade / recursos disponíveis.

Para a implementação de alguns itens será necessário acesso total ao servidor via SSH, ou painel de controle equivalente, como Webmin, ou similares.

## 1) CND (Cloudflare ou similar)
Recomendamos o uso do [Cloudflare](https://www.cloudflare.com/) ou CDN similar com o objetivo de evitar e bloquear possíveis ataques DDOS ao site.

## 2) Servidor Web 
*Necessário acesso **root** ao servidor.*
### 2.1) SFTP
Uso de SFTP seguro e criptografado
### 2.2) Firewall
Bloqueio de todas as portas externas, com excessão das portas 80, 443, e SFTP e SSH.
### 2.3) Portas
Alteração do número das portas padrão, como 21, 22, para outros números.
### 2.4) Fail2Ban
Uso da ferramenta [Fail2Ban](https://www.fail2ban.org/wiki/index.php/Main_Page) afim de bloquear qualquer tentativa via força bruta de acesso ao servidor através do SSH, SFTP, ou Ataque em Massa(DDOS).
### 2.5) Permissões de Pastas
Correta permissões de pastas conforme recomendação do [Wordpress](https://wordpress.org/support/article/changing-file-permissions/):
Folders       - 755
Files         - 644
wp-config.php - 600
.htaccess     – 644, ou 600

### 2.6) .htaccess 
>*Regras específicas para servidores Apache*

Incluir determinadas regras no arquivo .htaccess., sendo elas:

#### 2.6.1) X-Security Headers
Proteção contra ataque XSS, Click-Jacking, Content-Sniffing
```
# Extra Security Headers
<IfModule mod_headers.c>
  # X-XSS-Protection
  Header set X-XSS-Protection "1; mode=block"
  # X-Frame-Options
  Header always append X-Frame-Options SAMEORIGIN
  # X-Content-Type nosniff
  Header set X-Content-Type-Options nosniff
</IfModule>
```
*Referência.: [https://htaccessbook.com/increase-security-x-security-headers/](https://htaccessbook.com/increase-security-x-security-headers/)* 

#### 2.6.2) Bloquear Spiders Bad Bots
Bloquear bots ruins que prejudicam o site, ou buscam alguma forma de fraudar o site.
```
# Block Spiders Bad Bots
<IfModule mod_rewrite.c>
	RewriteEngine On 
	RewriteCond %{HTTP_USER_AGENT} ^BlackWidow [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Bot\ mailto:craftbot@yahoo.com [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^ChinaClaw [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Custo [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^DISCo [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Download\ Demon [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^eCatch [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^EirGrabber [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^EmailSiphon [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^EmailWolf [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Express\ WebPictures [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^ExtractorPro [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^EyeNetIE [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^FlashGet [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^GetRight [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^GetWeb! [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Go!Zilla [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Go-Ahead-Got-It [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^GrabNet [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Grafula [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^HMView [OR] 
	RewriteCond %{HTTP_USER_AGENT} HTTrack [NC,OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Image\ Stripper [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Image\ Sucker [OR] 
	RewriteCond %{HTTP_USER_AGENT} Indy\ Library [NC,OR] 
	RewriteCond %{HTTP_USER_AGENT} ^InterGET [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Internet\ Ninja [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^JetCar [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^JOC\ Web\ Spider [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^larbin [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^LeechFTP [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Mass\ Downloader [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^MIDown\ tool [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Mister\ PiX [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Navroad [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^NearSite [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^NetAnts [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^NetSpider [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Net\ Vampire [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^NetZIP [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Octopus [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Offline\ Explorer [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Offline\ Navigator [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^PageGrabber [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Papa\ Foto [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^pavuk [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^pcBrowser [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^RealDownload [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^ReGet [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^SiteSnagger [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^SmartDownload [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^SuperBot [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^SuperHTTP [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Surfbot [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^tAkeOut [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Teleport\ Pro [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^VoidEYE [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Web\ Image\ Collector [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Web\ Sucker [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebAuto [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebCopier [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebFetch [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebGo\ IS [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebLeacher [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebReaper [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebSauger [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Website\ eXtractor [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Website\ Quester [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebStripper [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebWhacker [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WebZIP [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Wget [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Widow [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^WWWOFFLE [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Xaldon\ WebSpider [OR] 
	RewriteCond %{HTTP_USER_AGENT} ^Zeus 
	RewriteRule ^.* - [F,L]
</IfModule>
``` 
*Referência.: [http://www.javascriptkit.com/howto/htaccess13.shtml](http://www.javascriptkit.com/howto/htaccess13.shtml)* 

#### 2.6.3) Bloquear acesso aos principais arquivos do Wordpress
Bloquear acesso via browser de qualquer tentativa de acesso ao arquivo de configuração, e ao XMLRpc (*avaliar caso a caso a necessidade*).
```
# Secure .htaccess file
<Files .htaccess>
	Order allow,deny
	Deny from all
</Files>

# Protect wpconfig.php
<files wp-config.php>
	order allow,deny
	deny from all
</files>

# Block WordPress xmlrpc.php
<Files xmlrpc.php>
	order deny,allow
	deny from all
</Files>
```
>Caso seja possível o arquivo wp-config.php deve ser movido para uma pasta abaixo da raiz do servidor web, afim de impossibilitar qualquer acesso através do navegador. 
Referência>: [https://wordpress.org/support/article/hardening-wordpress/#securing-wp-config-php](https://wordpress.org/support/article/hardening-wordpress/#securing-wp-config-php)

#### 2.6.4) Proteção para a pasta wp-includes
Bloquear acessos diretos aos arquivos da pasta "wp-includes" do core do Wordress.
```
# Block the include-only files.
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^wp-admin/includes/ - [F,L]
RewriteRule !^wp-includes/ - [S=3]
RewriteRule ^wp-includes/[^/]+\.php$ - [F,L]
RewriteRule ^wp-includes/js/tinymce/langs/.+\.php - [F,L]
RewriteRule ^wp-includes/theme-compat/ - [F,L]
</IfModule>
```
*Referência.: [https://wordpress.org/support/article/hardening-wordpress/#securing-wp-includes](https://wordpress.org/support/article/hardening-wordpress/#securing-wp-includes)* 


#### 2.6.5) Proteção adicional a XSS e XST e bloqueio de injeção de Conteúdo e Scripts
Bloquear alguns ataques comuns de XSS (cross-site scripting), como também contra injeções de script e tentativas de modificar variáveis globais e de solicitação do PHP.
```
# Add Protection XSS, XST, Script Injection, Block Track and Trace
<IfModule mod_rewrite.c>
	Options +FollowSymLinks
	RewriteEngine On
	RewriteCond %{QUERY_STRING} base64_encode.*\(.*\) [OR]
	RewriteCond %{QUERY_STRING} (\<|%3C).*script.*(\>|%3E) [NC,OR]
	RewriteCond %{QUERY_STRING} (\<|%3C).*iframe.*(\>|%3E) [NC,OR]
	RewriteCond %{QUERY_STRING} GLOBALS(=|\[|\%[0-9A-Z]{0,2}) [OR]
	RewriteCond %{QUERY_STRING} _REQUEST(=|\[|\%[0-9A-Z]{0,2})
	RewriteRule ^(.*)$ /index.php [F,L]
	RewriteEngine On
	RewriteCond %{REQUEST_METHOD} ^(TRACE|TRACK)
	RewriteRule .* – [F]
	RewriteEngine On
	RewriteCond %{REQUEST_METHOD} ^TRACE
	RewriteRule .* – [F]
</IfModule>
```
*Referências.:* 
*[https://wp-mix.com/block-xss-htaccess/](https://wp-mix.com/block-xss-htaccess/)*
*[https://perishablepress.com/disable-trace-and-track-for-better-security/](https://perishablepress.com/disable-trace-and-track-for-better-security/)* 

#### 2.6.6) Proteção contra servidores Proxies
Bloquear acessos através de servidores proxy de realizarem comentários ou acessar o painel administrador (wp-admin).
```
# Block Proxy Comments and Login
<IfModule mod_rewrite.c>
	RewriteCond %{REQUEST_METHOD} =POST
	RewriteCond %{HTTP:VIA}                 !^$ [OR]
	RewriteCond %{HTTP:FORWARDED}           !^$ [OR]
	RewriteCond %{HTTP:USERAGENT_VIA}       !^$ [OR]
	RewriteCond %{HTTP:X_FORWARDED_FOR}     !^$ [OR]
	RewriteCond %{HTTP:PROXY_CONNECTION}    !^$ [OR]
	RewriteCond %{HTTP:XPROXY_CONNECTION}   !^$ [OR]
	RewriteCond %{HTTP:HTTP_PC_REMOTE_ADDR} !^$ [OR]
	RewriteCond %{HTTP:HTTP_CLIENT_IP}      !^$
	RewriteCond %{REQUEST_URI} !^/(wp-login.php|wp-admin/|wp-content/plugins/|wp-includes/).* [NC]
	RewriteRule .* - [F,NS,L]
</IfModule>
```
*Referência.: [https://perishablepress.com/how-to-block-proxy-servers-via-htaccess/](https://perishablepress.com/how-to-block-proxy-servers-via-htaccess/)* 

#### 2.6.7) Proteção para ataques de SPAM no login e comentários
Bloqueio de Comentários, Postagens, Formulários e Login realizados por SPAM Bots. 
```
# Stop spam attack logins and comments
# Replace *example.com.* with website domain, ex.: *google.com*
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteCond %{REQUEST_METHOD} POST
	RewriteCond %{REQUEST_URI} .(wp-comments-post|wp-login)\.php*
	RewriteCond %{HTTP_REFERER} !.*example.com.* [OR]
	RewriteCond %{HTTP_USER_AGENT} ^$
	RewriteRule (.*) http://%{REMOTE_ADDR}/$1 [R=301,L]
</ifModule>
```

*Referência.: [https://wordpress.org/support/article/brute-force-attacks/#deny-access-to-no-referrer-requests](https://wordpress.org/support/article/brute-force-attacks/#deny-access-to-no-referrer-requests)* 

#### 2.6.8) Proteção contra Scan de Autores
Bloqueio de Scan nos nomes de autores para utilização posterior em ataque de força bruta no formulário de login.
```
# Block author scans
<IfModule mod_rewrite.c>
	RewriteEngine On
	RewriteBase /
	RewriteCond %{QUERY_STRING} (author=\d+) [NC]
	RewriteRule .* - [F]
	# END block author scans
</ifModule>
```
*Referência.: [https://www.wpbeginner.com/wp-tutorials/how-to-discourage-brute-force-by-blocking-author-scans-in-wordpress/](https://www.wpbeginner.com/wp-tutorials/how-to-discourage-brute-force-by-blocking-author-scans-in-wordpress/)*

## 3) Banco de Dados MySQL
Para utilização do Wordpress, o usuário do banco de dados não precisa de permissões complexas, somente as básicas,: SELECT, INSERT, UPDATE e DELETE., demais privilégios podem ser revogadas.
>**Obs.:**  Algumas atualizações necessitam de permissões DROP, ALTER e GRANT
> Antes de aplicar esta regra analisar a real necessidade, como também o plano de manutenção e backups.  

*Referência.: [https://wordpress.org/support/article/hardening-wordpress/#restricting-database-user-privileges](https://wordpress.org/support/article/hardening-wordpress/#restricting-database-user-privileges)*

## 4) Wordpress
Atividades a serem executadas dentro do Wordpress e suas configurações.
### 4.1) Usuários
### 4.1.1) Senhas
Não utilizar em hipótese alguma senhas pouco seguras, como:
````
12345
admin
nomedosite
meunome
````
### 4.1.2) Usuário "admin"
Nunca utilizar o usuário como admin, ou root, caso já exista um usuário nomeado admin, criar outro usuário administrador e remover este.
### 4.2) Login
### 4.2.1) Captcha
A Captcha no formulário de login, protege contra acessos de bots, ou robôs.
Recomendamos a utilização do plugin.: 
[reCaptcha by BestWebSoft](https://wordpress.org/plugins/google-captcha/)
### 4.2.2) Limitação de Tentativas de Login
Uma técnica de segurança consiste em bloquear por algumas horas ou dias usuários que "erram" o usuário ou senha  de acesso ao site por algum número de vezes seguidas.
Com isso conseguimos bloquear tentativas automáticas (força bruta) ao painel administrativo do Wordpress.
Recomendamos a utilização do plugin.:
[Limit Login Attempts Reloaded](https://br.wordpress.org/plugins/limit-login-attempts-reloaded/) 
### 4.3) Backups
Depender somente dos backups do serviço de hospedagem utilizado é perigoso e não recomendado por vários motivos, sendo alguns deles.:
- A maioria dos hosts faz um backup / snapshot do servidor inteiro, no caso de uma catástrofe ele consegue recuperar a maquina e o seu conteúdo, mas caso o seu servidor seja compartilhado a empresa nunca irá restaurar um snapshot por causa de um cliente especifico.
- Alguns hosts possuem backup somente das configurações da hospedagem, em caso de algum problema ele reconfigura o seu espaço de hospedagem garantindo o funcionamento do servidor, mas o conteúdo dentro dele não, com isso você perderia todos os seus dados.
- Os poucos hosts que realizam e fornecem backups do conteúdo do seu site, não o realizam dentro um cronograma razoável ou a retenção é insuficiente.

Recomendamos o uso de plugins para a realização de backups, seguindo o seguinte cronograma e o número de retenções mínimos
**Sites com atualizações diárias de conteúdo.:**
Banco de Dados: Backup Diário, com Retenção de 7 Dias.
Arquivos: Backup Diário, com Retenção de 7 Dias.
**Sites com atualizações semanais.:**
Banco de Dados: Backup Diário, com Retenção de 15 Dias.
Arquivos: Backup Diário, com Retenção de 15 Dias.
**Sites com atualizações quinzenais.:**
Banco de Dados: Backup Semanal, com Retenção de 4 Semanas.
Arquivos: Backup  Semanal, com Retenção de 4 Semanas.
**Sites com atualizações esporádicas.:**
Banco de Dados: Backup Semanal, com Retenção de 8 Semanas.
Arquivos: Backup  Semanal, com Retenção de 8 Semanas.

Além de backups full mensais e anuais. 
Se possível o armazenamento de todos os backups, ou alguns em um espaço separado do site, ou um serviço de cloud externo.

Recomendamos a utilização do plugin.:
[Updraft Plus](https://wordpress.org/plugins/updraftplus/)

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.
