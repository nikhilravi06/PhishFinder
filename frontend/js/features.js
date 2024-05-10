/*
$('a').click(function(){
    alert("You are about to go to "+$(this).attr('href'));
});
*/




var result = {};

//---------------------- 1. IP Address ----------------------

var url = window.location.href;
var urlDomain = window.location.hostname;

// Define regular expressions for IP address detection
var ipRegex = /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/;
var hexIpRegex = /\b0x[\da-fA-F]{8}\b/; // Assuming the IP address is represented in hex

// Check if the domain matches IP address patterns
if (ipRegex.test(urlDomain) || hexIpRegex.test(urlDomain)) { 
    result["IP Address"] = "1"; // Likely a phishing indicator
} else {
    result["IP Address"] = "-1"; // Unlikely to be a phishing indicator
}
console.log(result);

//---------------------- 2. URL Length ----------------------

var url = window.location.href;
var urlLength = url.length;

// Define thresholds for URL length classification
var SHORT_URL_THRESHOLD = 50;
var MEDIUM_URL_THRESHOLD = 75;

// Check URL length and classify based on thresholds
if (urlLength < SHORT_URL_THRESHOLD) {
    result["URL Length"] = "-1"; // Short URL
} else if (urlLength >= SHORT_URL_THRESHOLD && urlLength <= MEDIUM_URL_THRESHOLD) {
    result["URL Length"] = "0"; // Medium URL
} else {
    result["URL Length"] = "1"; // Long URL
}
//---------------------- 3. Tiny URL ----------------------

var onlyDomain = urlDomain.replace('www.', '');

// Define a more accurate threshold for Tiny URLs
var TINY_URL_THRESHOLD = 10; // Example threshold based on analysis

// Check if the domain name length meets the threshold
if (onlyDomain.length < TINY_URL_THRESHOLD) {
    result["Tiny URL"] = "1"; // Domain length indicates a Tiny URL
} else {
    result["Tiny URL"] = "-1"; // Domain length indicates a non-Tiny URL
}

//---------------------- 4. @ Symbol ----------------------

// Define a more accurate regex pattern to detect "@" symbol in the URL
var atSymbolRegex = /@/;

// Check if the URL contains "@" symbol using the regex pattern
if (atSymbolRegex.test(url)) { 
    result["@ Symbol"] = "1"; // "@" symbol detected in the URL
} else {
    result["@ Symbol"] = "-1"; // "@" symbol not detected in the URL
}

//---------------------- 5. Redirecting using // ----------------------

// Define a more accurate threshold for detecting double slashes in the URL
var DOUBLE_SLASH_THRESHOLD = 7; // Example threshold based on analysis

// Check if the URL contains double slashes beyond the threshold
if (url.lastIndexOf("//") > DOUBLE_SLASH_THRESHOLD) {
    result["Redirecting using //"] = "1"; // Redirecting using double slashes detected
} else {
    result["Redirecting using //"] = "-1"; // No redirecting using double slashes detected
}

//---------------------- 6. (-) Prefix/Suffix in domain ----------------------

// Define a more accurate regex pattern to detect "-" prefix or suffix in the domain name
var dashRegex = /^-|-$|[^-](-)[^-]/;

// Check if the domain name contains "-" prefix or suffix using the regex pattern
if (dashRegex.test(urlDomain)) { 
    result["(-) Prefix/Suffix in domain"] = "1"; // "-" prefix or suffix detected in the domain name
} else {
    result["(-) Prefix/Suffix in domain"] = "-1"; // No "-" prefix or suffix detected in the domain name
}

//---------------------- 7. No. of Sub Domains ----------------------

// Define a more accurate regular expression pattern to count subdomains
var subdomainRegex = /^((?:[^.]+)\.)+/;

// Extract subdomains from the domain name
var subdomains = onlyDomain.match(subdomainRegex);

// Check the number of subdomains
if (subdomains && subdomains.length > 0) { 
    var numberOfSubdomains = subdomains[0].split('.').length - 1; // Exclude the root domain
    if (numberOfSubdomains === 1) {
        result["No. of Sub Domains"] = "-1"; // Single subdomain
    } else if (numberOfSubdomains === 2) {
        result["No. of Sub Domains"] = "0"; // Two subdomains (likely a standard domain structure)
    } else {
        result["No. of Sub Domains"] = "1"; // More than two subdomains (potentially suspicious)
    }
} else {
    result["No. of Sub Domains"] = "-1"; // No subdomains found
}
//---------------------- 8. HTTPS ----------------------

// Extract the protocol from the URL
var protocol = url.split('://')[0];

// Check if the protocol is HTTPS
if (protocol.toLowerCase() === 'https') {
    result["HTTPS"] = "-1"; // HTTPS protocol detected
} else {
    result["HTTPS"] = "1"; // HTTP or other protocol detected
}

//---------------------- 10. Favicon ----------------------

var favicon = undefined;
var nodeList = document.getElementsByTagName("link");
for (var i = 0; i < nodeList.length; i++) {
    var rel = nodeList[i].getAttribute("rel");
    var href = nodeList[i].getAttribute("href");
    
    // Check if the link tag corresponds to favicon
    if (rel && (rel.toLowerCase() === "icon" || rel.toLowerCase() === "shortcut icon") && href) {
        favicon = href;
        break; // Exit loop once favicon is found
    }
}

// Check if favicon URL is found and analyze it
if (!favicon) {
    result["Favicon"] = "-1"; // No favicon found
} else if (favicon.length <= 12) {
    result["Favicon"] = "-1"; // Suspiciously short favicon URL
} else {
    // Check if favicon URL contains the domain name
    var domainRegex = new RegExp(urlDomain, 'gi');
    if (domainRegex.test(favicon)) {
        result["Favicon"] = "-1"; // Favicon URL contains the domain name (potentially legitimate)
    } else {
        result["Favicon"] = "1"; // Favicon URL is different from the domain (potentially suspicious)
    }
}

// Optionally, perform further analysis or actions based on the favicon analysis
// For example, you could use this information as a feature for an ML model


//---------------------- 11. Using Non-Standard Port ----------------------

// Extract the port number from the URL
var port = new URL(url).port;

// Check if a port is specified and if it's non-standard
if (port && !['80', '443'].includes(port)) {
    result["Port"] = "1"; // Non-standard port detected
} else {
    result["Port"] = "-1"; // Standard port (or no port) detected
}

//---------------------- 12. HTTPS in URL's domain part ----------------------

// Extract the protocol from the URL
var protocol = new URL(url).protocol;

// Check if the protocol is HTTPS
if (protocol && protocol.toLowerCase() === 'https:') {
    result["HTTPS in URL's domain part"] = "1"; // HTTPS protocol detected in the domain part of the URL
} else {
    result["HTTPS in URL's domain part"] = "-1"; // HTTPS protocol not detected in the domain part of the URL
}

//---------------------- 13. Request URL ----------------------

var imgTags = document.getElementsByTagName("img");
var phishCount = 0;
var legitCount = 0;

// Create a regex pattern to match the domain part of the URL
var domainRegex = new RegExp(onlyDomain, 'gi');

for (var i = 0; i < imgTags.length; i++) {
    var src = imgTags[i].getAttribute("src");
    if (!src) continue;
    
    // Check if the source URL belongs to the same domain
    if (domainRegex.test(src)) {
        legitCount++;
    } else if (src.charAt(0) === '/' && src.charAt(1) !== '/') {
        legitCount++;
    } else {
        phishCount++;
    }
}

// Calculate the percentage of phishing requests
var totalCount = phishCount + legitCount;
var outRequest = (phishCount / totalCount) * 100;

// Classify the request URL based on the phishing percentage
if (outRequest < 22) {
    result["Request URL"] = "-1"; // Likely legitimate requests
} else if (outRequest >= 22 && outRequest < 61) {
    result["Request URL"] = "0"; // Potentially suspicious requests
} else {
    result["Request URL"] = "1"; // Likely phishing requests
}


//---------------------- 14. URL of Anchor ----------------------

var aTags = document.getElementsByTagName("a");
var phishCount = 0;
var legitCount = 0;
var allhrefs = "";

// Create a regex pattern to match the domain part of the URL
var domainRegex = new RegExp(onlyDomain, 'gi');

for (var i = 0; i < aTags.length; i++) {
    var hrefs = aTags[i].getAttribute("href");
    if (!hrefs) continue;
    allhrefs += hrefs + "       ";
    
    // Check if the href attribute points to the same domain
    if (domainRegex.test(hrefs)) {
        legitCount++;
    } else if (hrefs.charAt(0) === '#' || (hrefs.charAt(0) === '/' && hrefs.charAt(1) !== '/')) {
        legitCount++;
    } else {
        phishCount++;
    }
}

// Calculate the percentage of phishing anchor URLs
var totalCount = phishCount + legitCount;
var outRequest = (phishCount / totalCount) * 100;

// Classify the anchor URLs based on the phishing percentage
if (outRequest < 31) {
    result["Anchor"] = "-1"; // Likely legitimate anchor URLs
} else if (outRequest >= 31 && outRequest <= 67) {
    result["Anchor"] = "0"; // Potentially suspicious anchor URLs
} else {
    result["Anchor"] = "1"; // Likely phishing anchor URLs
}


//---------------------- 15. Links in script and link ----------------------

var mTags = document.getElementsByTagName("meta");
var sTags = document.getElementsByTagName("script");
var lTags = document.getElementsByTagName("link");
var phishCount = 0;
var legitCount = 0;
var allhrefs = "";

// Create a regex pattern to match the domain part of the URL
var domainRegex = new RegExp(onlyDomain, 'gi');

// Process script tags
allhrefs += "sTags  ";
for (var i = 0; i < sTags.length; i++) {
    var sTag = sTags[i].getAttribute("src");
    if (sTag != null) {
        allhrefs += sTag + "      ";
        
        // Check if the source URL belongs to the same domain
        if (domainRegex.test(sTag) || (sTag.charAt(0) === '/' && sTag.charAt(1) !== '/')) {
            legitCount++;
        } else {
            phishCount++;
        }
    }
}

// Process link tags
allhrefs += "      lTags   ";
for (var i = 0; i < lTags.length; i++) {
    var lTag = lTags[i].getAttribute("href");
    if (!lTag) continue;
    allhrefs += lTag + "       ";
    
    // Check if the href attribute points to the same domain
    if (domainRegex.test(lTag) || (lTag.charAt(0) === '/' && lTag.charAt(1) !== '/')) {
        legitCount++;
    } else {
        phishCount++;
    }
}

// Calculate the percentage of phishing script and link URLs
var totalCount = phishCount + legitCount;
var outRequest = (phishCount / totalCount) * 100;

// Classify the script and link URLs based on the phishing percentage
if (outRequest < 17) {
    result["Script & Link"] = "-1"; // Likely legitimate script and link URLs
} else if (outRequest >= 17 && outRequest <= 81) {
    result["Script & Link"] = "0"; // Potentially suspicious script and link URLs
} else {
    result["Script & Link"] = "1"; // Likely phishing script and link URLs
}


//---------------------- 16. Server Form Handler ----------------------

var forms = document.getElementsByTagName("form");
var res = "-1";

// Create a regex pattern to match the domain part of the URL
var domainRegex = new RegExp(onlyDomain, 'gi');

for (var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    
    // Check if the action attribute is empty or missing
    if (!action || action.trim() === "") {
        res = "1"; // SFH detected (action attribute empty or missing)
        break;
    } else if (!(action.charAt(0) === "/" || action.toLowerCase().startsWith("http://") || action.toLowerCase().startsWith("https://") || domainRegex.test(action))) {
        res = "0"; // Potential SFH detected
    }
}

result["SFH"] = res;


//---------------------- 17. Submitting to mail ----------------------

var forms = document.getElementsByTagName("form");
var res = "-1";

for (var i = 0; i < forms.length; i++) {
    var action = forms[i].getAttribute("action");
    var method = forms[i].getAttribute("method");

    // Check if the form action starts with "mailto:" and method is "get"
    if (action && action.toLowerCase().startsWith("mailto:") && (!method || method.toLowerCase() === "get")) {
        res = "1"; // Form submits data via email
        break;
    }
}

result["mailto"] = res;


//---------------------- 23. Using iFrame ----------------------

var iframes = document.getElementsByTagName("iframe");
var hasIframes = false;

for (var i = 0; i < iframes.length; i++) {
    var src = iframes[i].getAttribute("src");
    
    // Check if the iframe src is not empty and not equal to "about:blank"
    if (src && src.trim() !== "" && src.toLowerCase() !== "about:blank") {
        hasIframes = true;
        break;
    }
}

result["iFrames"] = hasIframes ? "1" : "-1";


//---------------------- Sending the result  ----------------------

chrome.runtime.sendMessage(result, function(response) {
    console.log(result);
    //console.log(response);
});

chrome.runtime.onMessage.addListener(
    function(request, sender, sendResponse) {
      if (request.action == "alert_user")
        alert("Warning!!! This seems to be a phishing website.");
      return Promise.resolve("Dummy response to keep the console quiet");
    }
);