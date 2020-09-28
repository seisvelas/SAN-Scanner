package burp;

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
    private ArrayList<String> scannedDomains;
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
                    stdout.println(SAN);
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
                        SANs.add((String)item.get(1));
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
