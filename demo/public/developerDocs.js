const docs = {

    docsDeveloperPortal: {
        docs:
            `
#Developer Portal 

`,
        code:
            ``
    },

    docsFhirBundle: {
        docs:
            `
## Fhir Bundle

__FHIR Bundle__ resource of type "collection" that includes all required FHIR resources (content + identity resources)  

See: [Modeling W3C Verifiable Credentials in FHIR](https://smarthealth.cards/credential-modeling/)


The __Fhir Bundle__ is expected in the following form:  

    {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            "<<FHIR Resource>>", 
            "<<FHIR Resource>>", 
            "..."
        ]
    }

<br/>

Download a sample __Fhir Bundle__ from [https://smarthealth.cards/examples/example-00-a-fhirBundle.json](https://smarthealth.cards/examples/example-00-a-fhirBundle.json)  


<input type="button" id='buttonDownloadSample' value="Download Sample" onclick="downloadFhirBundleSample()" />  

<br/><br/> 
__Paste your Fhir Bundle in the text box below:__
<br/> 

`,
        code:
            `
## Keys

See: [Generating and resolving cryptographic keys](https://smarthealth.cards/#protocol-details)  


### Issuer Public Key  

See:  [Determining keys associated with an issuer](https://smarthealth.cards/#determining-keys-associated-with-an-issuer)  
This public key will be used to verify the JWS signature and must be available at:  

<div style="display: inline-block">
<label>https:</label>
<input type="text" id='textIssuer' placeholder="contoso.com/issuer"
    style="width: 300px;" />
<label>/.well-known/jwks.json</label>
</div>

<br/><br/>

### Issuer Signing Key  

The credential payload will be signed with a private ES256 key.  

The __Signing Key__ is expected in the following form:  

    {
        "kty": "EC",
        "kid": "LR8EPRFYkdyreMNakALHRoq9ce3jaVbb9tyzji4jUzY",
        "use": "sig",
        "alg": "ES256",
        "crv": "P-256",
        "x": "Xm6UNA7d5BmR1LyrOdq9vuOw92AQiMl9ZfRh2u1fTDI",
        "y": "B_11Uf_Wzx-1Va8hx_E2-AX7KpJf9LXGQTHQmqchQOg",
        "d": "Kxhn2ve8W3KZPPLfNaXklghC9u5kDrzgt40dbSwWAKY"
    }



Generate a new sample ES256 key for creating a JWS signature:  

<input type="button" id='buttonGenerateKey' value="Generate Key" onclick="generateKeyPair()" />

<br/><br/>
  

__Paste your ES256 private key below in JWK format:__  
&nbsp;  

`
    },

    docsValidateFhirBundle: {
        docs:
            `
## Validate Fhir Bundle

See: [Modeling W3C Verifiable Credentials in FHIR](https://smarthealth.cards/credential-modeling/)


 

The __Fhir Bundle__ is expected in the following form:  

    {
        "resourceType": "Bundle",
        "type": "collection",
        "entry": [
            "<<FHIR Resource>>", 
            "<<FHIR Resource>>", 
            "..."
        ]
    }


Download a sample Fhir Bundle from [https://smarthealth.cards/examples/example-00-a-fhirBundle.json](https://smarthealth.cards/examples/example-00-a-fhirBundle.json)  


<input type="button" id='buttonDownloadSample' value="Download Sample" onclick="downloadFhirBundleSample()" />  
&nbsp;  

`,
        code:
            ``
    },

    docsCreateCredential: {
        docs:
            `
## Create Credential

See: [Modeling W3C Verifiable Credentials in FHIR](https://smarthealth.cards/credential-modeling/)

The __Fhir Bundle__ above is inserted into a Verifiable Credential (VC) structure. 
The issuer field \`iss\` is set to the value you enter into the __Issuer Signing Key__ text field above.  
&nbsp;  

`,
        code:
            `
Notice that the __vs.credentialSubject.fhirBundle__ contains the Fhir Bundle from above.  
\`\`\`
{
    "iss": "https://smarthealth.cards/examples/issuer",
    "nbr": 1617925250718,
    "vc": {
        "@context": [
            "https://www.w3.org/2018/credentials/v1"
        ],
        "type": [
            "VerifiableCredential",
            "https://smarthealth.cards#health-card",
            "https://smarthealth.cards#immunization",
            "https://smarthealth.cards#covid19"
        ],
        "credentialSubject": {
            "fhirVersion": "4.0.1",
            "fhirBundle": {
                "<<FHIR Bundle>>"
            }
        }
    }
}
\`\`\`
&nbsp;  

`
    },

    docsMinimizePayload: {
        docs:
            `
## Minify Payload  

See: [Health Cards are Small](https://smarthealth.cards/#health-cards-are-small)

The Verfiable Credential (VC) above is minified, all extraneous white-space is removed.

&nbsp;  


`,
        code:
            ``
    },

    docsDeflatePayload: {
        docs:
            `
## Deflate Payload  

See: [Health Cards are Small](https://smarthealth.cards/#health-cards-are-small)

The minified credential above is deflated (compressed) using the DEFLATE algorithm.  
The deflated binary data is represented as Base64url below for display purposes.  
<br/>


`,
        code:
            ``
    },

    docsAddHeader: {
        docs:
            `
## Add JWS Header  

See: [Health Cards are Small/JWS Header](https://smarthealth.cards/#health-cards-are-small)  

The JWS header is in the following form:  

    {"zip":"DEF","alg":"ES256","kid":"<<key thumbprint>>"}  

\`"kid"\` is equal to the base64url-encoded SHA-256 JWK Thumbprint of the key (see [RFC7638](https://tools.ietf.org/html/rfc7638))


The header is then base64url-encoded:

    eyJ6aXAiOiJERUYiLCJhbGciOiJFUzI1NiIsImtpZCI6IjEyMzQ1Njc4OTAxMjM0NTY3ODkwMTIzNDU2Nzg5MCJ9.<<Deflated JWS Payload>>

<br/>  

__Note:__ Additional line-breaks at the periods '.' below have been added for display purposes only.

<br/>

`,
        code:``
    },

    docsSignPayload: {
        docs:
            `
## Sign Payload  

See: [Signing Health Cards](https://smarthealth.cards/#signing-health-cards)  

The header and compressed payload are signed using the private key supplied in the __Issuer Signing Key__ field above.  

The signature is appended to the header.payload string resulting in header.payload.signature  
This form represents a _compact JWS_ string.  

<br/>  

__Note:__ Additional line-breaks at the periods '.' below have been added for display purposes only.

<br/> 


`,
        code:  ``
    },

    docsSmartHealthCard: {
        docs:
            `
## SMART Health Card  

See: [SMART Health Card](https://smarthealth.cards/#user-retrieves-health-cards)  

The SMART Health Card is formed by wrapping the JWS above in a \`{ verifiableCredential[ <jws> [, <jws>, ...] }\`  structure  
&nbsp;  


`,
        code: ``
    },

    docsNumericEncode: {
        docs:
            `
## Numeric Encoding  

See: [Encoding Chunks as QR Codes](https://smarthealth.cards/#encoding-chunks-as-qr-codes)  

Encoding the SMART Health Card as a Numerical Encoded QR-Code.  

&nbsp;  

`
,
        code:
            ``
    },

    docsQRCode: {
        docs:
            `
## QR Encoding  

See: [Creating a QR code (or a set of QR codes) from a Health Card JWS](https://smarthealth.cards/#creating-a-qr-code-or-a-set-of-qr-codes-from-a-health-card-jws)    

The Numeric encoded data is used to construct a QR-Code image.  

&nbsp;  

`,
        code: ``

    }






}