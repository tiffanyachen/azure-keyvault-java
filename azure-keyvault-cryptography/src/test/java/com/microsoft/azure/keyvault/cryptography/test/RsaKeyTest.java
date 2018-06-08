package com.microsoft.azure.keyvault.cryptography.test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.AzureResponseBuilder;
import com.microsoft.azure.keyvault.KeyIdentifier;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.cryptography.RsaKey;
import com.microsoft.azure.keyvault.cryptography.algorithms.Rs256;
import com.microsoft.azure.keyvault.cryptography.algorithms.Rsa15;
import com.microsoft.azure.keyvault.cryptography.algorithms.RsaOaep;
import com.microsoft.azure.keyvault.cryptography.algorithms.RsaesOaep256;
import com.microsoft.azure.keyvault.models.KeyBundle;
import com.microsoft.azure.keyvault.models.KeyOperationResult;
import com.microsoft.azure.keyvault.models.KeyVerifyResult;
import com.microsoft.azure.keyvault.requests.ImportKeyRequest;
import com.microsoft.azure.keyvault.webkey.JsonWebKey;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyOperation;
import com.microsoft.azure.keyvault.webkey.JsonWebKeySignatureAlgorithm;
import com.microsoft.azure.keyvault.webkey.JsonWebKeyType;
import com.microsoft.azure.management.resources.core.InterceptorManager;
import com.microsoft.azure.management.resources.core.TestBase;
import com.microsoft.azure.management.resources.fluentcore.utils.ResourceManagerThrottlingInterceptor;
import com.microsoft.azure.serializer.AzureJacksonAdapter;
import com.microsoft.rest.LogLevel;
import com.microsoft.rest.RestClient;
import com.microsoft.rest.credentials.ServiceClientCredentials;
import com.microsoft.rest.interceptors.LoggingInterceptor;

public class RsaKeyTest {

    private static TestBase.TestMode testMode = null;

    protected InterceptorManager interceptorManager = null;

    protected final static String ZERO_SUBSCRIPTION = "00000000-0000-0000-0000-000000000000";
    protected final static String ZERO_TENANT = "00000000-0000-0000-0000-000000000000";
    private static final String PLAYBACK_URI_BASE = "http://localhost:";
    protected static String playbackUri = null;

    static KeyVaultClient keyVaultClient;
    final static String KEY_NAME = "otherkey2";
    static String VAULT_URI;

    // A Content Encryption Key, or Message. This value is kept consistent with the
    // .NET
    // unit test cases to enable cross platform testing.
    static final byte[] CEK = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, (byte) 0x88, (byte) 0x99, (byte) 0xAA,
            (byte) 0xBB, (byte) 0xCC, (byte) 0xDD, (byte) 0xEE, (byte) 0xFF };
    static final String CrossPlatformHash = "qPrtarvzXBKksm5A9v6xnXNtkARcg7n5ox9jjTI+aBE=";
    static final String CrossPlatformSignature = "RaNc+8WcWxplS8I7ynJLSoLJKz+dgBvrZhIGH3VFlTTyzu7b9d+lpaV9IKhzCNBsgSysKhgL7EZwVCOTBZ4m6xvKSXqVFXYaBPyBTD7VoKPMYMW6ai5x6xV5XAMaZPfMkff3Deg/RXcc8xQ28FhYuUa8yly01GySY4Hk55anEvb2wBxSy1UGun/0LE1lYH3C3XEgSry4cEkJHDJl1hp+wB4J/noXOqn5ECGU+/4ehBJOyW1gtUH0/gRe8yXnDH0AXepHRyH8iBHLWlKX1r+1/OrMulqOoi82RZzJlTyEz9X+bsQhllqGF6n3hdLS6toH9o7wUtwYNqSx82JuQT6iMg==";

    private Provider _provider = null;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
    }

    @AfterClass
    public static void tearDownAfterClass() throws Exception {
    }

    @BeforeClass
    public static void setUp() throws Exception {
        initTestMode();
        initPlaybackUri();
    }

    @Rule
    public TestName testName = new TestName();

    @Before
    public void beforeMethod() throws Exception {
        VAULT_URI = System.getenv("VAULT_URI");

        RestClient restClient;
        ServiceClientCredentials credentials = createTestCredentials();
        interceptorManager = InterceptorManager.create(testName.getMethodName(), testMode);

        if (isRecordMode()) {
            restClient = new RestClient.Builder().withBaseUrl("https://{vaultBaseUrl}")
                    .withSerializerAdapter(new AzureJacksonAdapter())
                    .withResponseBuilderFactory(new AzureResponseBuilder.Factory()).withCredentials(credentials)
                    .withLogLevel(LogLevel.NONE)
                    .withNetworkInterceptor(new LoggingInterceptor(LogLevel.BODY_AND_HEADERS))
                    .withNetworkInterceptor(interceptorManager.initInterceptor())
                    .withInterceptor(new ResourceManagerThrottlingInterceptor()).build();

            interceptorManager.addTextReplacementRule("https://management.azure.com/", playbackUri + "/");
            interceptorManager.addTextReplacementRule("https://graph.windows.net/", playbackUri + "/");

            keyVaultClient = new KeyVaultClient(restClient);
        } else { // is Playback Mode
            restClient = new RestClient.Builder().withBaseUrl(playbackUri + "/")
                    .withSerializerAdapter(new AzureJacksonAdapter())
                    .withResponseBuilderFactory(new AzureResponseBuilder.Factory()).withCredentials(credentials)
                    .withLogLevel(LogLevel.NONE)
                    .withNetworkInterceptor(new LoggingInterceptor(LogLevel.BODY_AND_HEADERS))
                    .withNetworkInterceptor(interceptorManager.initInterceptor())
                    .withInterceptor(new ResourceManagerThrottlingInterceptor()).build();
            keyVaultClient = new KeyVaultClient(restClient);
        }
    }

    @After
    public void tearDown() throws Exception {
    }

    protected void setProvider(Provider provider) {
        _provider = provider;
    }

    @Test
    public void testRsa15() throws Exception {

        RsaKey key = getTestRsaKey();

        // Wrap and Unwrap
        Pair<byte[], String> wrapped = key.wrapKeyAsync(CEK, Rsa15.ALGORITHM_NAME).get();
        byte[] unwrapped = key.unwrapKeyAsync(wrapped.getLeft(), wrapped.getRight()).get();

        // Assert
        assertEquals(Rsa15.ALGORITHM_NAME, wrapped.getRight());
        assertArrayEquals(CEK, unwrapped);

        // Encrypt and Decrypt
        Triple<byte[], byte[], String> encrypted = key.encryptAsync(CEK, null, null, Rsa15.ALGORITHM_NAME).get();
        byte[] decrypted = key.decryptAsync(encrypted.getLeft(), null, null, null, encrypted.getRight()).get();

        // Assert
        assertEquals(Rsa15.ALGORITHM_NAME, encrypted.getRight());
        assertArrayEquals(CEK, decrypted);

        key.close();
    }

    @Test
    public void testRsaOaep() throws Exception {

        RsaKey key = getTestRsaKey();

        // Wrap and Unwrap
        Pair<byte[], String> wrapped = key.wrapKeyAsync(CEK, RsaOaep.ALGORITHM_NAME).get();
        byte[] unwrapped = key.unwrapKeyAsync(wrapped.getLeft(), wrapped.getRight()).get();

        // Assert
        assertEquals(RsaOaep.ALGORITHM_NAME, wrapped.getRight());
        assertArrayEquals(CEK, unwrapped);

        // Encrypt and Decrypt
        Triple<byte[], byte[], String> encrypted = key.encryptAsync(CEK, null, null, RsaOaep.ALGORITHM_NAME).get();
        byte[] decrypted = key.decryptAsync(encrypted.getLeft(), null, null, null, encrypted.getRight()).get();

        // Assert
        assertEquals(RsaOaep.ALGORITHM_NAME, encrypted.getRight());
        assertArrayEquals(CEK, decrypted);

        key.close();
    }

    @Test
    public void testRsaesOaep256() throws Exception {

        RsaKey key = getTestRsaKey();

        // Wrap and Unwrap
        Pair<byte[], String> wrapped = key.wrapKeyAsync(CEK, RsaesOaep256.ALGORITHM_NAME).get();
        byte[] unwrapped = key.unwrapKeyAsync(wrapped.getLeft(), wrapped.getRight()).get();

        // Assert
        assertEquals(RsaesOaep256.ALGORITHM_NAME, wrapped.getRight());
        assertArrayEquals(CEK, unwrapped);

        // Encrypt and Decrypt
        Triple<byte[], byte[], String> encrypted = key.encryptAsync(CEK, null, null, RsaesOaep256.ALGORITHM_NAME).get();
        byte[] decrypted = key.decryptAsync(encrypted.getLeft(), null, null, null, encrypted.getRight()).get();

        // Assert
        assertEquals(RsaesOaep256.ALGORITHM_NAME, encrypted.getRight());
        assertArrayEquals(CEK, decrypted);

        key.close();
    }

    @Test
    public void testDefaultAlgorithm() throws Exception {

        RsaKey key = getTestRsaKey();

        assertEquals(RsaOaep.ALGORITHM_NAME, key.getDefaultEncryptionAlgorithm());
        assertEquals(RsaOaep.ALGORITHM_NAME, key.getDefaultKeyWrapAlgorithm());
        assertEquals(Rs256.ALGORITHM_NAME, key.getDefaultSignatureAlgorithm());

        // Wrap and Unwrap
        Pair<byte[], String> wrapped = key.wrapKeyAsync(CEK, key.getDefaultKeyWrapAlgorithm()).get();
        byte[] unwrapped = key.unwrapKeyAsync(wrapped.getLeft(), wrapped.getRight()).get();

        // Assert
        assertEquals(RsaOaep.ALGORITHM_NAME, wrapped.getRight());
        assertArrayEquals(CEK, unwrapped);

        // Encrypt and Decrypt
        Triple<byte[], byte[], String> encrypted = key
                .encryptAsync(CEK, null, null, key.getDefaultEncryptionAlgorithm()).get();
        byte[] decrypted = key.decryptAsync(encrypted.getLeft(), null, null, null, encrypted.getRight()).get();

        // Assert
        assertEquals(RsaOaep.ALGORITHM_NAME, encrypted.getRight());
        assertArrayEquals(CEK, decrypted);

        key.close();
    }

    @Test
    public void testSignVerify() throws Exception {

        RsaKey key = getTestRsaKey();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(CEK);

        byte[] crossPlatformHash = Base64.decodeBase64(CrossPlatformHash);
        byte[] crossPlatformSignature = Base64.decodeBase64(CrossPlatformSignature);

        // Check the hash
        assertNotNull(hash);
        assertEquals(32, hash.length);
        assertArrayEquals(hash, crossPlatformHash);

        Pair<byte[], String> signature = key.signAsync(hash, "RS256").get();
        boolean result = key.verifyAsync(hash, signature.getLeft(), "RS256").get();

        // Check the signature
        assertTrue(result);
        assertArrayEquals(crossPlatformSignature, signature.getLeft());

        // Now prove we can verify the cross platform signature
        result = key.verifyAsync(hash, Base64.decodeBase64(CrossPlatformSignature), "RS256").get();

        assertTrue(result);

        key.close();
    }

    @Test
    public void testSignVerifyPs256() throws Exception {
        signVerifyLocal("PS256", "SHA-256");
    }

    @Test
    public void testSignVerifyPs384() throws Exception {
        signVerifyLocal("PS384", "SHA-384");
    }

    @Test
    public void testSignVerifyPs512() throws Exception {
        signVerifyLocal("PS512", "SHA-512");
    }

    private void signVerifyLocal(String algName, String digestAlg) throws Exception {
        RsaKey key = getTestRsaKey();

        MessageDigest digest = MessageDigest.getInstance(digestAlg);
        byte[] hash = digest.digest(CEK);

        Pair<byte[], String> signature = key.signAsync(hash, algName).get();
        boolean result = key.verifyAsync(hash, signature.getLeft(), algName).get();

        assertTrue(result);

        key.close();
    }

    @Test
    public void testSignVerifyServicePs256() throws Exception {
        signVerifyWithService(KEY_NAME, JsonWebKeySignatureAlgorithm.PS256, "SHA-256");
    }

    @Test
    public void testSignVerifyServicePs384() throws Exception {
        signVerifyWithService(KEY_NAME, JsonWebKeySignatureAlgorithm.PS384, "SHA-384");
    }

    @Test
    public void testSignVerifyServicePs512() throws Exception {
        signVerifyWithService(KEY_NAME, JsonWebKeySignatureAlgorithm.PS512, "SHA-512");
    }

    private void signVerifyWithService(String keyName, JsonWebKeySignatureAlgorithm algorithm, String digestAlg)
            throws Exception {

        JsonWebKey testKey = importTestKey(keyName);

        RsaKey key = new RsaKey(testKey.kid(), getWellKnownKey());

        KeyIdentifier keyId = new KeyIdentifier(testKey.kid());

        // Test variables
        byte[] plainText = new byte[100];
        new Random(0x1234567L).nextBytes(plainText);
        MessageDigest md = MessageDigest.getInstance(digestAlg);
        md.update(plainText);
        byte[] digest = md.digest();
        byte[] signature;

        KeyOperationResult result;
        KeyVerifyResult verifyResult;

        // Using kid WO version
        {
            signature = key.signAsync(digest, algorithm.toString()).get().getLeft();
            verifyResult = keyVaultClient.verify(keyId.baseIdentifier(), algorithm, digest, signature);
            Assert.assertEquals(new Boolean(true), verifyResult.value());
        }

        {
            result = keyVaultClient.sign(keyId.baseIdentifier(), algorithm, digest);
            signature = result.result();
            Assert.assertTrue(key.verifyAsync(digest, signature, algorithm.toString()).get());
        }
        key.close();
    }

    private static JsonWebKey importTestKey(String keyName) throws Exception {

        KeyBundle keyBundle = new KeyBundle();
        JsonWebKey key = JsonWebKey.fromRSA(getTestKeyMaterial());

        key.withKty(JsonWebKeyType.RSA);
        key.withKeyOps(Arrays.asList(JsonWebKeyOperation.ENCRYPT, JsonWebKeyOperation.DECRYPT, JsonWebKeyOperation.SIGN,
                JsonWebKeyOperation.VERIFY, JsonWebKeyOperation.WRAP_KEY, JsonWebKeyOperation.UNWRAP_KEY));

        System.out.println(key.kid());

        keyBundle = keyVaultClient
                .importKey(new ImportKeyRequest.Builder(VAULT_URI, KEY_NAME, key).withHsm(false).build());

        return keyBundle.key();
    }

    private static KeyPair getTestKeyMaterial() throws Exception {
        return getWellKnownKey();
    }

    private static KeyPair getWellKnownKey() throws Exception {
        BigInteger modulus = new BigInteger(
                "27266783713040163753473734334021230592631652450892850648620119914958066181400432364213298181846462385257448168605902438305568194683691563208578540343969522651422088760509452879461613852042845039552547834002168737350264189810815735922734447830725099163869215360401162450008673869707774119785881115044406101346450911054819448375712432746968301739007624952483347278954755460152795801894283389540036131881712321193750961817346255102052653789197325341350920441746054233522546543768770643593655942246891652634114922277138937273034902434321431672058220631825053788262810480543541597284376261438324665363067125951152574540779");
        BigInteger publicExponent = new BigInteger("65537");
        BigInteger privateExponent = new BigInteger(
                "10466613941269075477152428927796086150095892102279802916937552172064636326433780566497000814207416485739683286961848843255766652023400959086290344987308562817062506476465756840999981989957456897020361717197805192876094362315496459535960304928171129585813477132331538577519084006595335055487028872410579127692209642938724850603554885478763205394868103298473476811627231543504190652483290944218004086457805431824328448422034887148115990501701345535825110962804471270499590234116100216841170344686381902328362376624405803648588830575558058257742073963036264273582756620469659464278207233345784355220317478103481872995809");
        BigInteger primeP = new BigInteger(
                "175002941104568842715096339107566771592009112128184231961529953978142750732317724951747797764638217287618769007295505214923187971350518217670604044004381362495186864051394404165602744235299100790551775147322153206730562450301874236875459336154569893255570576967036237661594595803204808064127845257496057219227");
        BigInteger primeQ = new BigInteger(
                "155807574095269324897144428622185380283967159190626345335083690114147315509962698765044950001909553861571493035240542031420213144237033208612132704562174772894369053916729901982420535940939821673277140180113593951522522222348910536202664252481405241042414183668723338300649954708432681241621374644926879028977");
        BigInteger primeExponentP = new BigInteger(
                "79745606804504995938838168837578376593737280079895233277372027184693457251170125851946171360348440134236338520742068873132216695552312068793428432338173016914968041076503997528137698610601222912385953171485249299873377130717231063522112968474603281996190849604705284061306758152904594168593526874435238915345");
        BigInteger primeExponentQ = new BigInteger(
                "80619964983821018303966686284189517841976445905569830731617605558094658227540855971763115484608005874540349730961777634427740786642996065386667564038755340092176159839025706183161615488856833433976243963682074011475658804676349317075370362785860401437192843468423594688700132964854367053490737073471709030801");
        BigInteger crtCoefficient = new BigInteger(
                "2157818511040667226980891229484210846757728661751992467240662009652654684725325675037512595031058612950802328971801913498711880111052682274056041470625863586779333188842602381844572406517251106159327934511268610438516820278066686225397795046020275055545005189953702783748235257613991379770525910232674719428");

        KeySpec publicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
        KeySpec privateKeySpec = new RSAPrivateCrtKeySpec(modulus, publicExponent, privateExponent, primeP, primeQ,
                primeExponentP, primeExponentQ, crtCoefficient);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec));
    }

    @Test
    public void testToFromJsonWebKey() throws Exception {
        RsaKey key = getTestRsaKey();
        JsonWebKey jwk = key.toJsonWebKey();
        jwk.withKid("new kid");
        // setting kid
        RsaKey sameKey = RsaKey.fromJsonWebKey(jwk, true, _provider);
        JsonWebKey jwkSame = sameKey.toJsonWebKey();
        jwkSame.withKid("new kid");
        assertEquals(jwk, jwkSame);
    }

    private RsaKey getTestRsaKey() throws Exception {
        String jwkString = "{\"kty\":\"RSA\",\"n\":\"rZ8pnmXkhfmmgNWVVdtNcYy2q0OAcCGIpeFzsN9URqJsiBEiWQfxlUxFTbM4kVWPqjauKt6byvApBGEeMA7Qs8kxwRVP-BD4orXRe9VPgliM92rH0UxQWHmCHUe7G7uUAFPwbiDVhWuFzELxNa6Kljg6Z9DuUKoddmQvlYWj8uSunofCtDi_zzlZKGYTOYJma5IYScHNww1yjLp8-b-Be2UdHbrPkCv6Nuwi6MVIKjPpEeRQgfefRmxDBJQKY3OfydMXZmEwukYXVkUcdIP8XwG2OxnfdRK0oAo0NDebNNVuT89k_3AyZLTr1KbDmx1nnjwa8uB8k-uLtcOC9igbTw\",\"e\":\"AQAB\",\"d\":\"H-z7hy_vVJ9yeZBMtIvt8qpQUK_J51STPwV085otcgud72tPKJXoW2658664ASl9kGwbnLBwb2G3-SEunuGqiNS_PGUB3niob6sFSUMRKsPDsB9HfPoOcCZvwZiWFGRqs6C7vlR1TuJVqRjKJ_ffbf4K51oo6FZPspx7j4AShLAwLUSQ60Ld5QPuxYMYZIMpdVbMVIVHJ26pR4Y18e_0GYmEGnbF5N0HkwqQmfmTiIK5aoGnD3GGgqHeHmWBwh6_WAq90ITLcX_zBeqQUgBSj-Z5v61SroO9Eang36T9mMoYrcPpYwemtAOb4HhQYDj8dCCfbeOcVmvZ9UJKWCX2oQ\",\"dp\":\"HW87UpwPoj3lPI9B9K1hJFeuGgarpakvtHuk1HpZ5hXWFGAJiXoWRV-jvYyjoM2k7RpSxPyuuFFmYHcIxiGFp2ES4HnP0BIhKVa2DyugUxIEcMK53C43Ub4mboJPZTSC3sapKgAmA2ue624sapWmshTPpx9qnUP2Oj3cSMkgMGE\",\"dq\":\"RhwEwb5FYio0GS2tmul8FAYsNH7JDehwI1yUApnTiakhSenFetml4PYyVkKR4csgLZEi3RY6J3R8Tg-36zrZuF7hxhVJn80L5_KETSpfEI3jcrXMVg4SRaMsWLY9Ahxflt2FJgUnHOmWRLmP6_hmaTcxxSACjbyUd_HhwNavD5E\",\"qi\":\"wYPZ4lKIslA1w3FaAzQifnNLABYXXUZ_KAA3a8T8fuxkdE4OP3xIFX7WHhnmBd6uOFiEcGoeq2jNQqDg91rV5661-5muQKcvp4uUsNId5rQw9EZw-kdDcwMtVFTEBfvVuyp83X974xYAHn1Jd8wWohSwrpi1QuH5cQMR5Fm6I1A\",\"p\":\"74Ot7MgxRu4euB31UWnGtrqYPjJmvbjYESS43jfDfo-s62ggV5a39P_YPg6oosgtGHNw0QDxunUOXNu9iriaYPf_imptRk69bKN8Nrl727Y-AaBYdLf1UZuwz8X07FqHAH5ghYpk79djld8QvkUUJLpx6rzcW8BJLTOi46DtzZE\",\"q\":\"uZJu-qenARIt28oj_Jlsk-p_KLnqdczczZfbRDd7XNp6csGLa8R0EyYqUB4xLWELQZsX4tAu9SaAO62tuuEy5wbOAmOVrq2ntoia1mGQSJdoeVq6OqtN300xVnaBc3us0rm8C6-824fEQ1PWXoulXLKcSqBhFT-hQahsYi-kat8\"}";
        ObjectMapper mapper = new ObjectMapper();
        JsonWebKey jwk = null;

        jwk = mapper.readValue(jwkString, JsonWebKey.class);

        return new RsaKey("foo", jwk.toRSA(true, _provider));
    }

    private static AuthenticationResult getAccessToken(String authorization, String resource) throws Exception {

        String clientId = System.getenv("arm.clientid");

        if (clientId == null) {
            throw new Exception("Please inform arm.clientid in the environment settings.");
        }

        String clientKey = System.getenv("arm.clientkey");
        String username = System.getenv("arm.username");
        String password = System.getenv("arm.password");

        AuthenticationResult result = null;
        ExecutorService service = null;
        try {
            service = Executors.newFixedThreadPool(1);
            AuthenticationContext context = new AuthenticationContext(authorization, false, service);

            Future<AuthenticationResult> future = null;

            if (clientKey != null && password == null) {
                ClientCredential credentials = new ClientCredential(clientId, clientKey);
                future = context.acquireToken(resource, credentials, null);
            }

            if (password != null && clientKey == null) {
                future = context.acquireToken(resource, clientId, username, password, null);
            }

            if (future == null) {
                throw new Exception(
                        "Missing or ambiguous credentials - please inform exactly one of arm.clientkey or arm.password in the environment settings.");
            }

            result = future.get();
        } finally {
            service.shutdown();
        }

        if (result == null) {
            throw new RuntimeException("authentication result was null");
        }
        return result;
    }

    private static ServiceClientCredentials createTestCredentials() throws Exception {
        return new KeyVaultCredentials() {

            @Override
            public String doAuthenticate(String authorization, String resource, String scope) {
                try {
                    if (isRecordMode()) {
                        AuthenticationResult authResult = getAccessToken(authorization, resource);
                        return authResult.getAccessToken();
                    } else {
                        return "";
                    }
                } catch (Exception ex) {
                    throw new RuntimeException(ex);
                }
            }
        };
    }

    @After
    public void afterMethod() throws IOException {
        interceptorManager.finalizeInterceptor();
    }

    private static void initPlaybackUri() throws IOException {
        if (isPlaybackMode()) {
            // 11080 and 11081 needs to be in sync with values in jetty.xml file
            playbackUri = PLAYBACK_URI_BASE + "11080";
        } else {
            playbackUri = PLAYBACK_URI_BASE + "1234";
        }
    }

    public static boolean isPlaybackMode() {
        if (testMode == null)
            try {
                initTestMode();
            } catch (IOException e) {
                e.printStackTrace();
                throw new RuntimeException("Can't init test mode.");
            }
        return testMode == TestBase.TestMode.PLAYBACK;
    }

    public static boolean isRecordMode() {
        return !isPlaybackMode();
    }

    private static void initTestMode() throws IOException {
        String azureTestMode = System.getenv("AZURE_TEST_MODE");
        if (azureTestMode != null) {
            if (azureTestMode.equalsIgnoreCase("Record")) {
                testMode = TestBase.TestMode.RECORD;
            } else if (azureTestMode.equalsIgnoreCase("Playback")) {
                testMode = TestBase.TestMode.PLAYBACK;
            } else {
                throw new IOException("Unknown AZURE_TEST_MODE: " + azureTestMode);
            }
        } else {
            // System.out.print("Environment variable 'AZURE_TEST_MODE' has not been set
            // yet. Using 'Playback' mode.");
            testMode = TestBase.TestMode.PLAYBACK;
        }
    }

}
