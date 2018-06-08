package com.microsoft.azure.keyvault.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import com.microsoft.aad.adal4j.AuthenticationContext;
import com.microsoft.aad.adal4j.AuthenticationResult;
import com.microsoft.aad.adal4j.ClientCredential;
import com.microsoft.azure.AzureResponseBuilder;
import com.microsoft.azure.keyvault.KeyIdentifier;
import com.microsoft.azure.keyvault.KeyVaultClient;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;
import com.microsoft.azure.keyvault.cryptography.RsaKey;
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
public class AzureKeyVaultCryptographyIntegrationTests {

    private static TestBase.TestMode testMode = null;

    protected InterceptorManager interceptorManager = null;

    protected final static String ZERO_SUBSCRIPTION = "00000000-0000-0000-0000-000000000000";
    protected final static String ZERO_TENANT = "00000000-0000-0000-0000-000000000000";
    private static final String PLAYBACK_URI_BASE = "http://localhost:";
    private static final String PLAYBACK_VAULT = "https://test-vault.vault.azure.net";
        
    protected static String playbackUri = null;

    static KeyVaultClient keyVaultClient;
    
    final static String KEY_NAME = "otherkey2";
    static String VAULT_URI;
    

    @Rule
    public TestName testName = new TestName();

 
    
    @BeforeClass
    public static void setUp() throws Exception {
        initTestMode();
        initPlaybackUri();
    }

    @Before
    public void beforeMethod() throws Exception {

        RestClient restClient;
        ServiceClientCredentials credentials = createTestCredentials();
        interceptorManager = InterceptorManager.create(testName.getMethodName(), testMode);

        if (isRecordMode()) {
            VAULT_URI = System.getenv("VAULT_URI");
            restClient = new RestClient.Builder().withBaseUrl("https://{vaultBaseUrl}")
                    .withSerializerAdapter(new AzureJacksonAdapter())
                    .withResponseBuilderFactory(new AzureResponseBuilder.Factory()).withCredentials(credentials)
                    .withLogLevel(LogLevel.NONE)
                    .withNetworkInterceptor(new LoggingInterceptor(LogLevel.BODY_AND_HEADERS))
                    .withNetworkInterceptor(interceptorManager.initInterceptor())
                    .withInterceptor(new ResourceManagerThrottlingInterceptor()).build();

            interceptorManager.addTextReplacementRule("https://management.azure.com/", playbackUri + "/");
            interceptorManager.addTextReplacementRule("https://graph.windows.net/", playbackUri + "/");
            interceptorManager.addTextReplacementRule(VAULT_URI, PLAYBACK_VAULT);
            keyVaultClient = new KeyVaultClient(restClient);
        } else { // is Playback Mode
            VAULT_URI = PLAYBACK_VAULT;
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
