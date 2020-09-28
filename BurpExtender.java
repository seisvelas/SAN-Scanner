package burp;

/* 
    Ideally we'd use a Burp library for networking, instead
    of Java's native URL() class. Unfortunately, the makeHttpRequest()
    method provided by Burp doesn't give us the means to
    analyze SSL certs.
    
    Other SSL related Burp extensions are also impacted by this limitation
    and resign themselves to the same approach used here. For example,
    SSL Scanner: https://github.com/portswigger/ssl-scanner
    Also uses java.net.URL.
    
    If Burp ever adds this functionality to their API, we should
    switch to that.
    
*/
import java.net.URL;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import java.net.MalformedURLException;
import java.util.List;
import java.util.Collection;

public class BurpExtender implements IBurpExtender, IHttpListener {   
    private PrintWriter stdout;
    private ArrayList<String> scannedDomains = new ArrayList<String>();
    private String SANAlertFormat = "SAN found for %s: %s"; // hostname, SAN
    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks cb;
    //
    // implement IBurpExtender
    //
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        cb = callbacks;
        // obtain an extension helpers object
        helpers = cb.getHelpers();
        
        // set our extension name
        cb.setExtensionName("SAN Scanner");
        
        // register ourselves as an HTTP listener
        cb.registerHttpListener(this);

        stdout = new PrintWriter(callbacks.getStdout(), true);

    }
    
    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // only process requests
        if (messageIsRequest) {
            IHttpService httpService = messageInfo.getHttpService();
            String hostname = httpService.getHost();
            if (!scannedDomains.contains(hostname)) {
                ArrayList<String> SANs = subjectAlternativeNames(hostname);
                for (String SAN : SANs) {
                    // Only alert the user if the SAN != the hostname (uninteresting)
                    if (!SAN.equals(hostname)) {
                        String SANAlert = String.format(SANAlertFormat, hostname, SAN);
                        cb.issueAlert(SANAlert);
                    }
                }
                scannedDomains.add(hostname);
            }
        }
    }

    // return array of SANs from hostname's TLS cert
    private ArrayList<String> subjectAlternativeNames(String hostname) {
        try {
            // todo: make sure return array has only unique values
            X509Certificate[] certs = getCerts(hostname);
            ArrayList<String> SANs = new ArrayList<String>();
            
            for (X509Certificate cert : certs) {
                Collection<List<?>> certSANs = cert.getSubjectAlternativeNames();
                try {
                    for (List item : certSANs) {
                        String SAN = (String)item.get(1);
                        SANs.add(SAN.replace("*.", ""));
                    }
                } catch (NullPointerException e) {
                    // cert has no SANs
                }
            }
            return SANs;
        } catch (Exception e) {
            e.printStackTrace(stdout);
            return new ArrayList<String>();
        }
    }

    private X509Certificate[] getCerts(String hostname) {
        // todo: cleaner exception handling
        try {
            URL httpsURL = new URL(String.format("https://%s", hostname));
            HttpsURLConnection connection = (HttpsURLConnection)httpsURL.openConnection();
            connection.connect();
            X509Certificate[] certs = (X509Certificate[])connection.getServerCertificates();
            return certs;
        } catch (Exception e) {
            return new X509Certificate[0];
        }
    }
}
