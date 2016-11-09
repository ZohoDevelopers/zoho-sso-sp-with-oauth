<?php

include 'Assertion.php';
class Response
{

    private $assertions;

    private $destination;
    
    private $certificates;
    private $signatureData;


    public function __construct(DOMElement $xml = NULL)
    {

        $this->assertions = array();
        $this->certificates = array();

        if ($xml === NULL) {
            return;
        }
        
        $sig = Utilities::validateElement($xml);

        if ($sig != FALSE) {
            $this->certificates = $sig['Certificates'];
            $this->signatureData = $sig;
        }
        
        /* set the destination from saml response */
        if ($xml->hasAttribute('Destination')) {
            $this->destination = $xml->getAttribute('Destination');
        }
        
        for ($node = $xml->firstChild; $node !== NULL; $node = $node->nextSibling) {
            if ($node->namespaceURI !== 'urn:oasis:names:tc:SAML:2.0:assertion') {
                continue;
            }
            
            if ($node->localName === 'Assertion' || $node->localName === 'EncryptedAssertion') {
                $this->assertions[] = new Assertion($node);
            }
            
        }
    }

   
    public function getAssertions()
    {   
        return $this->assertions;
    }

  
    public function setAssertions(array $assertions)
    {
        $this->assertions = $assertions;
    }
    
    public function getDestination()
    {
        return $this->destination;
    }

   
    public function toUnsignedXML()
    {
        $root = parent::toUnsignedXML();

        foreach ($this->assertions as $assertion) {

            $assertion->toXML($root);
        }

        return $root;
    }

    public function getCertificates()
    {
        return $this->certificates;
    }

    public function getSignatureData()
    {
        return $this->signatureData;
    }
}
