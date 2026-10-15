import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.*;
import javax.security.auth.x500.X500Principal;

/** Local X.509 CA using standard JCA APIs; never changes system trust. */
final class TlsAuthority {
    private final PrivateKey key;
    final X509Certificate certificate;
    private final Map<String,SSLContext> contexts=new ConcurrentHashMap<>();
    private TlsAuthority(PrivateKey key,X509Certificate certificate){this.key=key;this.certificate=certificate;}
    static TlsAuthority create() throws Exception {
        KeyPair pair=keys();byte[] name=new X500Principal("CN=VULN Local Inspection CA, O=VULN").getEncoded();
        return new TlsAuthority(pair.getPrivate(),issue(pair.getPublic(),name,name,pair.getPrivate(),true,null));
    }
    static TlsAuthority load(Path path,char[] password) throws Exception {
        KeyStore store=KeyStore.getInstance("PKCS12");try(InputStream input=Files.newInputStream(path)){store.load(input,password);}PrivateKey key=(PrivateKey)store.getKey("rea-ca",password);X509Certificate cert=(X509Certificate)store.getCertificate("rea-ca");if(key==null||cert==null||cert.getBasicConstraints()<0)throw new GeneralSecurityException("Keystore não contém uma CA REA válida");cert.checkValidity();
        byte[] challenge=new byte[32];new SecureRandom().nextBytes(challenge);Signature check=Signature.getInstance("SHA256withRSA");check.initSign(key);check.update(challenge);byte[] signed=check.sign();check.initVerify(cert.getPublicKey());check.update(challenge);if(!check.verify(signed))throw new GeneralSecurityException("Chave e certificado não correspondem");return new TlsAuthority(key,cert);
    }
    void save(Path path,char[] password) throws Exception {if(password.length<12)throw new GeneralSecurityException("Use uma senha de pelo menos 12 caracteres");KeyStore store=KeyStore.getInstance("PKCS12");store.load(null,null);store.setKeyEntry("rea-ca",key,password,new java.security.cert.Certificate[]{certificate});Path temp=Files.createTempFile(path.toAbsolutePath().getParent(),".rea-ca-",".tmp");try{try(OutputStream output=Files.newOutputStream(temp)){store.store(output,password);}Files.move(temp,path,StandardCopyOption.REPLACE_EXISTING);}finally{Files.deleteIfExists(temp);}}
    void exportCertificate(Path path) throws Exception {Files.writeString(path,"-----BEGIN CERTIFICATE-----\n"+Base64.getMimeEncoder(64,new byte[]{10}).encodeToString(certificate.getEncoded())+"\n-----END CERTIFICATE-----\n",StandardCharsets.US_ASCII);}
    String fingerprint() throws Exception {return HexFormat.ofDelimiter(":").withUpperCase().formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));}
    SSLContext serverContext(String host) throws Exception {
        SSLContext cached=contexts.get(host);if(cached!=null)return cached;
        synchronized(contexts){cached=contexts.get(host);if(cached!=null)return cached;if(contexts.size()>256)contexts.clear();KeyPair pair=keys();byte[] name=new X500Principal("CN="+X500PrincipalEscaper.escape(host)+", O=VULN").getEncoded();X509Certificate leaf=issue(pair.getPublic(),certificate.getSubjectX500Principal().getEncoded(),name,key,false,host);KeyStore store=KeyStore.getInstance("PKCS12");store.load(null,null);char[] password=UUID.randomUUID().toString().toCharArray();store.setKeyEntry("leaf",pair.getPrivate(),password,new java.security.cert.Certificate[]{leaf,certificate});KeyManagerFactory km=KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());km.init(store,password);Arrays.fill(password,'\0');SSLContext context=SSLContext.getInstance("TLS");context.init(km.getKeyManagers(),null,new SecureRandom());contexts.put(host,context);return context;}
    }
    SSLContext trustingContext() throws Exception {KeyStore trust=KeyStore.getInstance("PKCS12");trust.load(null,null);trust.setCertificateEntry("rea-ca",certificate);TrustManagerFactory tm=TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());tm.init(trust);SSLContext context=SSLContext.getInstance("TLS");context.init(null,tm.getTrustManagers(),new SecureRandom());return context;}
    static KeyPair keys() throws Exception {KeyPairGenerator generator=KeyPairGenerator.getInstance("RSA");generator.initialize(2048);return generator.generateKeyPair();}
    static X509Certificate issue(PublicKey publicKey,byte[] issuer,byte[] subject,PrivateKey signer,boolean ca,String host) throws Exception {
        byte[] algorithm=seq(oid("1.2.840.113549.1.1.11"),der(5,new byte[0]));
        List<byte[]> extensions=new ArrayList<>();extensions.add(seq(oid("2.5.29.19"),der(1,new byte[]{(byte)255}),der(4,ca?seq(der(1,new byte[]{(byte)255})):seq())));extensions.add(seq(oid("2.5.29.15"),der(1,new byte[]{(byte)255}),der(4,der(3,ca?new byte[]{1,6}:new byte[]{5,(byte)160}))));
        if(!ca){extensions.add(seq(oid("2.5.29.37"),der(4,seq(oid("1.3.6.1.5.5.7.3.1")))));String bare=host.startsWith("[")?host.substring(1,host.length()-1):host;boolean ip=bare.matches("[0-9.]+")||bare.contains(":");byte[] san=ip?der(0x87,InetAddress.getByName(bare).getAddress()):der(0x82,IDN.toASCII(bare).getBytes(StandardCharsets.US_ASCII));extensions.add(seq(oid("2.5.29.17"),der(4,seq(san))));}
        Instant now=Instant.now();DateTimeFormatter time=DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        byte[] tbs=seq(der(0xa0,der(2,new byte[]{2})),der(2,new BigInteger(159,new SecureRandom()).add(BigInteger.ONE).toByteArray()),algorithm,issuer,seq(der(24,time.format(now.minusSeconds(60)).getBytes(StandardCharsets.US_ASCII)),der(24,time.format(now.plusSeconds(ca?315360000L:2592000L)).getBytes(StandardCharsets.US_ASCII))),subject,publicKey.getEncoded(),der(0xa3,seq(extensions.toArray(byte[][]::new))));
        Signature signature=Signature.getInstance("SHA256withRSA");signature.initSign(signer);signature.update(tbs);byte[] signed=signature.sign();byte[] bits=new byte[signed.length+1];System.arraycopy(signed,0,bits,1,signed.length);byte[] encoded=seq(tbs,algorithm,der(3,bits));X509Certificate cert=(X509Certificate)CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(encoded));cert.checkValidity();return cert;
    }
    static byte[] seq(byte[]...parts){ByteArrayOutputStream b=new ByteArrayOutputStream();for(byte[] part:parts)b.writeBytes(part);return der(0x30,b.toByteArray());}
    static byte[] der(int tag,byte[] value){ByteArrayOutputStream b=new ByteArrayOutputStream();b.write(tag);int n=value.length;if(n<128)b.write(n);else{int count=0;for(int x=n;x>0;x>>>=8)count++;b.write(0x80|count);for(int i=count-1;i>=0;i--)b.write(n>>>(i*8));}b.writeBytes(value);return b.toByteArray();}
    static byte[] oid(String text){String[] parts=text.split("\\.");ByteArrayOutputStream b=new ByteArrayOutputStream();b.write(Integer.parseInt(parts[0])*40+Integer.parseInt(parts[1]));for(int i=2;i<parts.length;i++){long value=Long.parseLong(parts[i]);byte[] temp=new byte[10];int at=9;temp[at]=(byte)(value&127);while((value>>>=7)>0)temp[--at]=(byte)(128|(value&127));b.write(temp,at,10-at);}return der(6,b.toByteArray());}
    static final class X500PrincipalEscaper {static String escape(String s){return s.replace("\\","\\\\").replace(",","\\,").replace("+","\\+").replace("=","\\=").replace("\"","\\\"").replace("<","\\<").replace(">","\\>").replace(";","\\;");}}
}
