const verifierDocs = {
  "scanQRCode": {
    "l": "<p><strong>Requirements for Scanner:</strong><br />\nThe QR Scanner requires that your browser has access to a camera.  </p>\n<p>When accessing the portal from a remote server, the browser will require a <strong>HTTPS</strong> connection to a access the camera.   </p>\n<p>When using <code>localhost</code>, <strong>HTTP</strong> is sufficient.  </p>\n<p>To Scan your QR code, try to align the QR code within the square overlay.  As camera resolutions may differ, you may have experiment with finding the best alignment. Make sure the QR-code is flat.</p>\n<p>Download a sample <strong>Numeric QR Code</strong> from <a href=\"https://smarthealth.cards/examples/example-00-f-qr-code-numeric-value-0.txt\">https://smarthealth.cards/examples/example-00-f-qr-code-numeric-value-0.txt</a>  </p>\n<p><input type=\"button\" id='buttonDownloadSample' value=\"Download Sample\" onclick=\"downloadNumericQRSample()\" /> </p>\n<p><br><br></p>",
    "r": ""
  },
  "decodeNumeric": {
    "l": "<h2 id=\"decodenumericencoding\">Decode Numeric Encoding</h2>\n<p>Converts the <code>shc:/567629095243206...</code> encoded data to the compact JWS format <strong>base64url</strong>.<strong>base64url</strong>.<strong>base64url</strong></p>\n<p>See: <a href=\"https://smarthealth.cards/#health-cards-are-encoded-as-compact-serialization-json-web-signatures-jws\">Health Cards are encoded as Compact Serialization JSON Web Signatures (JWS)</a></p>\n<blockquote>\n  <p><strong>Note:</strong> Additional line-breaks at the periods '.' below have been added for display purposes only.  </p>\n</blockquote>\n<p><br><br></p>",
    "r": ""
  },
  "decodeJWS": {
    "l": "<h2 id=\"decodecompactjws\">Decode Compact JWS</h2>\n<p>Decodes the period-separated base64url segments of the compact JWS string.  </p>\n<h4 id=\"jwsheader\">JWS Header</h4>\n<p>The header is decoded into a JSON string.</p>\n<h4 id=\"jwspayload\">JWS Payload</h4>\n<p>The payload is converted from base64url to bytes and then decompressed using the INFLATE algorithm into a JSON string.</p>\n<h4 id=\"jwssignature\">JWS Signature</h4>\n<p>The signature is a 64-byte ES256 signature. It remains in its base64url form here.</p>\n<p><br><br></p>",
    "r": ""
  },
  "extractPublicKey": {
    "l": "<h2 id=\"extractpublickeyurl\">Extract Public Key URL</h2>\n<p>Extracts the public key url from the iss field in the JWS payload field above.</p>\n<p><code>/.well-known/jwks.json</code> is appended to the end of the iss url.</p>\n<blockquote>\n  <p><strong>Note</strong> : you may enter an alternate url here to use in the following steps.  </p>\n</blockquote>\n<p>See: <a href=\"https://smarthealth.cards/#protocol-details\">Protocol Details</a> for more information on <code>/.well-known/jwks.json</code></p>\n<p><br><br></p>",
    "r": ""
  },
  "downloadKey": {
    "l": "<h2 id=\"downloadpublickeys\">Download Public Key(s)</h2>\n<p>Using the Public Key Url above, a key-set is downloaded as JSON.  </p>\n<p>The public key <code>kid</code> field must match the <code>kid</code> field in the JWS header.  </p>\n<blockquote>\n  <p><strong>Note</strong> : you may enter an alternate key-set here to use in the remaining steps.</p>\n</blockquote>\n<p><br><br></p>",
    "r": "<p>Sample keys in a Key-Set.  x5c entries are truncated for display.    </p>\n<pre><code>{\n    \"keys\": [\n        {\n            \"kty\": \"EC\",\n            \"kid\": \"3Kfdg-XwP-7gXyywtUfUADwBumDOPKMQx-iELL11W9s\",\n            \"use\": \"sig\",\n            \"alg\": \"ES256\",\n            \"crv\": \"P-256\",\n            \"x\": \"11XvRWy1I2S0EyJlyf_bWfw_TQ5CJJNLw78bHXNxcgw\",\n            \"y\": \"eZXwxvO1hvCY0KucrPfKo7yAyMT6Ajc3N7OkAB6VYy8\"\n        },\n        {\n            \"kty\": \"EC\",\n            \"kid\": \"bVKTnRwVq4YU9oLwwShYELnRtKop_MsCAjNklowYemg\",\n            \"use\": \"sig\",\n            \"alg\": \"ES256\",\n            \"x5c\": [\n                \"MIICBjCCAYygAwIBAgIUGgXqplmagmOhhHUnRDUnQhTKa...\",\n                \"MIICBjCCAWigAwIBAgIUWgu3m7SToFGJKDerCOQcMK5Al...\",\n                \"MIICMTCCAZOgAwIBAgIUB+niLVaidI3U3xO2i7niRkith...\",\n            ],\n            \"crv\": \"P-256\",\n            \"x\": \"f6GJiCnbnBaIm2jDaH_3UPC7Yl-x5yBAi5ddZ8v3Y_w\",\n            \"y\": \"jKcqirFw4G9v9gWTDCqAjvcCRQpbIK76bWqKBtseFzQ\"\n        }\n    ]\n}  \n</code></pre>\n<p><br></p>"
  },
  "verifySignature": {
    "l": "<h2 id=\"verifysignature\">Verify Signature</h2>\n<p>The signature field of the compact JWS is verified against the header and payload using the public key.  </p>\n<p>Signature verification results in a <strong>true</strong> or <strong>false</strong> value.  </p>\n<p>See: <a href=\"https://smarthealth.cards/#protocol-details\">Protocol Details</a> for more information on signatures.</p>\n<p><br><br></p>",
    "r": ""
  },
  "extractFhirBundle": {
    "l": "<h2 id=\"extractfhirbundle\">Extract FHIR Bundle</h2>\n<p>After signature verification, the FHIR Bundle is extracted from the JWS payload field and formatted for display.    </p>\n<p><br><br></p>",
    "r": ""
  }
}