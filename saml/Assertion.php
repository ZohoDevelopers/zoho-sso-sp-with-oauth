<?php

include_once 'Utilities.php';
class Assertion
{
    private $id;
    private $issueInstant;
    private $issuer;
    private $nameId;
    private $notBefore;
    private $notOnOrAfter;
    private $validAudiences;
    private $sessionNotOnOrAfter;
    private $sessionIndex;
    private $authnInstant;
    private $authnContextClassRef;
    private $authnContextDecl;
    private $authnContextDeclRef;
    private $AuthenticatingAuthority;
    private $attributes;
    private $nameFormat;
    private $signatureKey;
    private $certificates;
    private $signatureData;
    private $requiredEncAttributes;
    private $SubjectConfirmation;
    protected $wasSignedAtConstruction = FALSE;
	
    public function __construct(DOMElement $xml = NULL)
    {
        $this->id = Utilities::generateId();
        $this->issueInstant = Utilities::generateTimestamp();
        $this->issuer = '';
        $this->authnInstant = Utilities::generateTimestamp();
        $this->attributes = array();
        $this->nameFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
        $this->certificates = array();
        $this->AuthenticatingAuthority = array();
        $this->SubjectConfirmation = array();

        if ($xml === NULL) {
            return;
        }
        if (!$xml->hasAttribute('ID')) {
            throw new Exception('Missing ID attribute on SAML assertion.');
        }
        $this->id = $xml->getAttribute('ID');
        if ($xml->getAttribute('Version') !== '2.0') {
            /* Currently a very strict check. */
            throw new Exception('Unsupported version: ' . $xml->getAttribute('Version'));
        }
        $this->issueInstant = Utilities::xsDateTimeToTimestamp($xml->getAttribute('IssueInstant'));
		
        $issuer = Utilities::xpQuery($xml, './saml_assertion:Issuer');
        if (empty($issuer)) {
            throw new Exception('Missing <saml:Issuer> in assertion.');
        }
        $this->issuer = trim($issuer[0]->textContent);
		
        $this->parseConditions($xml);
        $this->parseAuthnStatement($xml);
        $this->parseAttributes($xml);
        $this->parseSignature($xml);
        $this->parseSubject($xml);
		//echo "Signature parsed";
    }

    /**
     * Parse subject in assertion.
     *
     * @param DOMElement $xml The assertion XML element.
     * @throws Exception
     */
    private function parseSubject(DOMElement $xml)
    {
        $subject = Utilities::xpQuery($xml, './saml_assertion:Subject');
        if (empty($subject)) {
            /* No Subject node. */

            return;
        } elseif (count($subject) > 1) {
            throw new Exception('More than one <saml:Subject> in <saml:Assertion>.');
        }

        $subject = $subject[0];

        $nameId = Utilities::xpQuery(
            $subject,
            './saml_assertion:NameID | ./saml_assertion:EncryptedID/xenc:EncryptedData'
        );
        if (empty($nameId)) {
            throw new Exception('Missing <saml:NameID> or <saml:EncryptedID> in <saml:Subject>.');
        } elseif (count($nameId) > 1) {
            throw new Exception('More than one <saml:NameID> or <saml:EncryptedD> in <saml:Subject>.');
        }
        $nameId = $nameId[0];
        if ($nameId->localName === 'EncryptedData') {
            /* The NameID element is encrypted. */
            $this->encryptedNameId = $nameId;
        } else {
            $this->nameId = Utilities::parseNameId($nameId);
        }
	
    }

    private function parseConditions(DOMElement $xml)
    {
        $conditions = Utilities::xpQuery($xml, './saml_assertion:Conditions');
        if (empty($conditions)) {
            /* No <saml:Conditions> node. */

            return;
        } elseif (count($conditions) > 1) {
            throw new Exception('More than one <saml:Conditions> in <saml:Assertion>.');
        }
        $conditions = $conditions[0];

        if ($conditions->hasAttribute('NotBefore')) {
            $notBefore = Utilities::xsDateTimeToTimestamp($conditions->getAttribute('NotBefore'));
            if ($this->notBefore === NULL || $this->notBefore < $notBefore) {
                $this->notBefore = $notBefore;
            }
        }
        if ($conditions->hasAttribute('NotOnOrAfter')) {
            $notOnOrAfter = Utilities::xsDateTimeToTimestamp($conditions->getAttribute('NotOnOrAfter'));
            if ($this->notOnOrAfter === NULL || $this->notOnOrAfter > $notOnOrAfter) {
                $this->notOnOrAfter = $notOnOrAfter;
            }
        }

        for ($node = $conditions->firstChild; $node !== NULL; $node = $node->nextSibling) {
            if ($node instanceof DOMText) {
                continue;
            }
            if ($node->namespaceURI !== 'urn:oasis:names:tc:SAML:2.0:assertion') {
                throw new Exception('Unknown namespace of condition: ' . var_export($node->namespaceURI, TRUE));
            }
            switch ($node->localName) {
                case 'AudienceRestriction':
                    $audiences = Utilities::extractStrings($node, 'urn:oasis:names:tc:SAML:2.0:assertion', 'Audience');
                    if ($this->validAudiences === NULL) {
                        /* The first (and probably last) AudienceRestriction element. */
                        $this->validAudiences = $audiences;

                    } else {
                        /*
                         * The set of AudienceRestriction are ANDed together, so we need
                         * the subset that are present in all of them.
                         */
                        $this->validAudiences = array_intersect($this->validAudiences, $audiences);
                    }
                    break;
                case 'OneTimeUse':
                    /* Currently ignored. */
                    break;
                case 'ProxyRestriction':
                    /* Currently ignored. */
                    break;
                default:
                    throw new Exception('Unknown condition: ' . var_export($node->localName, TRUE));
            }
        }

    }

 
    private function parseAuthnStatement(DOMElement $xml)
    {
        $authnStatements = Utilities::xpQuery($xml, './saml_assertion:AuthnStatement');
        if (empty($authnStatements)) {
            $this->authnInstant = NULL;

            return;
        } elseif (count($authnStatements) > 1) {
            throw new Exception('More that one <saml:AuthnStatement> in <saml:Assertion> not supported.');
        }
        $authnStatement = $authnStatements[0];

        if (!$authnStatement->hasAttribute('AuthnInstant')) {
            throw new Exception('Missing required AuthnInstant attribute on <saml:AuthnStatement>.');
        }
        $this->authnInstant = Utilities::xsDateTimeToTimestamp($authnStatement->getAttribute('AuthnInstant'));

        if ($authnStatement->hasAttribute('SessionNotOnOrAfter')) {
            $this->sessionNotOnOrAfter = Utilities::xsDateTimeToTimestamp($authnStatement->getAttribute('SessionNotOnOrAfter'));
        }

        if ($authnStatement->hasAttribute('SessionIndex')) {
            $this->sessionIndex = $authnStatement->getAttribute('SessionIndex');
        }

        $this->parseAuthnContext($authnStatement);
    }

  
    private function parseAuthnContext(DOMElement $authnStatementEl)
    {
        // Get the AuthnContext element
        $authnContexts = Utilities::xpQuery($authnStatementEl, './saml_assertion:AuthnContext');
        if (count($authnContexts) > 1) {
            throw new Exception('More than one <saml:AuthnContext> in <saml:AuthnStatement>.');
        } elseif (empty($authnContexts)) {
            throw new Exception('Missing required <saml:AuthnContext> in <saml:AuthnStatement>.');
        }
        $authnContextEl = $authnContexts[0];

        // Get the AuthnContextDeclRef (if available)
        $authnContextDeclRefs = Utilities::xpQuery($authnContextEl, './saml_assertion:AuthnContextDeclRef');
        if (count($authnContextDeclRefs) > 1) {
            throw new Exception(
                'More than one <saml:AuthnContextDeclRef> found?'
            );
        } elseif (count($authnContextDeclRefs) === 1) {
            $this->setAuthnContextDeclRef(trim($authnContextDeclRefs[0]->textContent));
        }

        // Get the AuthnContextDecl (if available)
        $authnContextDecls = Utilities::xpQuery($authnContextEl, './saml_assertion:AuthnContextDecl');
        if (count($authnContextDecls) > 1) {
            throw new Exception(
                'More than one <saml:AuthnContextDecl> found?'
            );
        } elseif (count($authnContextDecls) === 1) {
            $this->setAuthnContextDecl(new SAML2_XML_Chunk($authnContextDecls[0]));
        }

        // Get the AuthnContextClassRef (if available)
        $authnContextClassRefs = Utilities::xpQuery($authnContextEl, './saml_assertion:AuthnContextClassRef');
        if (count($authnContextClassRefs) > 1) {
            throw new Exception('More than one <saml:AuthnContextClassRef> in <saml:AuthnContext>.');
        } elseif (count($authnContextClassRefs) === 1) {
            $this->setAuthnContextClassRef(trim($authnContextClassRefs[0]->textContent));
        }

        // Constraint from XSD: MUST have one of the three
        if (empty($this->authnContextClassRef) && empty($this->authnContextDecl) && empty($this->authnContextDeclRef)) {
            throw new Exception(
                'Missing either <saml:AuthnContextClassRef> or <saml:AuthnContextDeclRef> or <saml:AuthnContextDecl>'
            );
        }

        $this->AuthenticatingAuthority = Utilities::extractStrings(
            $authnContextEl,
            'urn:oasis:names:tc:SAML:2.0:assertion',
            'AuthenticatingAuthority'
        );
    }

  
    private function parseAttributes(DOMElement $xml)
    {
        $firstAttribute = TRUE;
        $attributes = Utilities::xpQuery($xml, './saml_assertion:AttributeStatement/saml_assertion:Attribute');
        foreach ($attributes as $attribute) {
            if (!$attribute->hasAttribute('Name')) {
                throw new Exception('Missing name on <saml:Attribute> element.');
            }
            $name = $attribute->getAttribute('Name');

            if ($attribute->hasAttribute('NameFormat')) {
                $nameFormat = $attribute->getAttribute('NameFormat');
            } else {
                $nameFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
            }

            if ($firstAttribute) {
                $this->nameFormat = $nameFormat;
                $firstAttribute = FALSE;
            } else {
                if ($this->nameFormat !== $nameFormat) {
                    $this->nameFormat = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
                }
            }

            if (!array_key_exists($name, $this->attributes)) {
                $this->attributes[$name] = array();
            }

            $values = Utilities::xpQuery($attribute, './saml_assertion:AttributeValue');
            foreach ($values as $value) {
                $this->attributes[$name][] = trim($value->textContent);
            }
        }
    }

   
    private function parseSignature(DOMElement $xml)
    {
        /* Validate the signature element of the message. */
        $sig = Utilities::validateElement($xml);
        if ($sig !== FALSE) {
            $this->wasSignedAtConstruction = TRUE;
            $this->certificates = $sig['Certificates'];
            $this->signatureData = $sig;
        }
    }

 
    public function validate(XMLSecurityKey $key)
    {
        assert('$key->type === XMLSecurityKey::RSA_SHA1');

        if ($this->signatureData === NULL) {
            return FALSE;
        }

        Utilities::validateSignature($this->signatureData, $key);

        return TRUE;
    }

 
    public function getId()
    {
        return $this->id;
    }

  
    public function setId($id)
    {
        assert('is_string($id)');

        $this->id = $id;
    }

  
    public function getIssueInstant()
    {
        return $this->issueInstant;
    }

 
    public function setIssueInstant($issueInstant)
    {
        assert('is_int($issueInstant)');

        $this->issueInstant = $issueInstant;
    }

 
    public function getIssuer()
    {
        return $this->issuer;
    }

 
    public function setIssuer($issuer)
    {
        assert('is_string($issuer)');

        $this->issuer = $issuer;
    }


    public function getNameId()
    {
        if ($this->encryptedNameId !== NULL) {
            throw new Exception('Attempted to retrieve encrypted NameID without decrypting it first.');
        }

        return $this->nameId;
    }

   
    public function setNameId($nameId)
    {
        assert('is_array($nameId) || is_null($nameId)');

        $this->nameId = $nameId;
    }


    public function getNotBefore()
    {
        return $this->notBefore;
    }

  
    public function setNotBefore($notBefore)
    {
        assert('is_int($notBefore) || is_null($notBefore)');

        $this->notBefore = $notBefore;
    }


    public function getNotOnOrAfter()
    {
        return $this->notOnOrAfter;
    }

  
    public function setNotOnOrAfter($notOnOrAfter)
    {
        assert('is_int($notOnOrAfter) || is_null($notOnOrAfter)');

        $this->notOnOrAfter = $notOnOrAfter;
    }


    public function getValidAudiences()
    {
        return $this->validAudiences;
    }

  
    public function setValidAudiences(array $validAudiences = NULL)
    {
        $this->validAudiences = $validAudiences;
    }

  
    public function getAuthnInstant()
    {
        return $this->authnInstant;
    }

    public function setAuthnInstant($authnInstant)
    {
        assert('is_int($authnInstant) || is_null($authnInstant)');

        $this->authnInstant = $authnInstant;
    }

  
    public function getSessionNotOnOrAfter()
    {
        return $this->sessionNotOnOrAfter;
    }


    public function setSessionNotOnOrAfter($sessionNotOnOrAfter)
    {
        assert('is_int($sessionNotOnOrAfter) || is_null($sessionNotOnOrAfter)');

        $this->sessionNotOnOrAfter = $sessionNotOnOrAfter;
    }

    public function getSessionIndex()
    {
        return $this->sessionIndex;
    }

   
    public function setSessionIndex($sessionIndex)
    {
        assert('is_string($sessionIndex) || is_null($sessionIndex)');

        $this->sessionIndex = $sessionIndex;
    }

    public function getAuthnContext()
    {
        if (!empty($this->authnContextClassRef)) {
            return $this->authnContextClassRef;
        }
        if (!empty($this->authnContextDeclRef)) {
            return $this->authnContextDeclRef;
        }
        return NULL;
    }

 
    public function setAuthnContext($authnContext)
    {
        $this->setAuthnContextClassRef($authnContext);
    }


    public function getAuthnContextClassRef()
    {
        return $this->authnContextClassRef;
    }

   
    public function setAuthnContextClassRef($authnContextClassRef)
    {
        assert('is_string($authnContextClassRef) || is_null($authnContextClassRef)');

        $this->authnContextClassRef = $authnContextClassRef;
    }

  
    public function setAuthnContextDecl(SAML2_XML_Chunk $authnContextDecl)
    {
        if (!empty($this->authnContextDeclRef)) {
            throw new Exception(
                'AuthnContextDeclRef is already registered! May only have either a Decl or a DeclRef, not both!'
            );
        }

        $this->authnContextDecl = $authnContextDecl;
    }

 
    public function getAuthnContextDecl()
    {
        return $this->authnContextDecl;
    }

 
    public function setAuthnContextDeclRef($authnContextDeclRef)
    {
        if (!empty($this->authnContextDecl)) {
            throw new Exception(
                'AuthnContextDecl is already registered! May only have either a Decl or a DeclRef, not both!'
            );
        }

        $this->authnContextDeclRef = $authnContextDeclRef;
    }

 
    public function getAuthnContextDeclRef()
    {
        return $this->authnContextDeclRef;
    }


    public function getAuthenticatingAuthority()
    {
        return $this->AuthenticatingAuthority;
    }

   
    public function setAuthenticatingAuthority($authenticatingAuthority)
    {
        $this->AuthenticatingAuthority = $authenticatingAuthority;
    }

 
    public function getAttributes()
    {
        return $this->attributes;
    }

    
    public function setAttributes(array $attributes)
    {
        $this->attributes = $attributes;
    }

   
    public function getAttributeNameFormat()
    {
        return $this->nameFormat;
    }

    public function setAttributeNameFormat($nameFormat)
    {
        assert('is_string($nameFormat)');

        $this->nameFormat = $nameFormat;
    }

    public function getSubjectConfirmation()
    {
        return $this->SubjectConfirmation;
    }

    public function setSubjectConfirmation(array $SubjectConfirmation)
    {
        $this->SubjectConfirmation = $SubjectConfirmation;
    }

    public function getSignatureKey()
    {
        return $this->signatureKey;
    }

    public function getSignatureData()
    {
        return $this->signatureData;
    }

    public function setSignatureKey(XMLsecurityKey $signatureKey = NULL)
    {
        $this->signatureKey = $signatureKey;
    }

    public function setCertificates(array $certificates)
    {
        $this->certificates = $certificates;
    }

    public function getCertificates()
    {
        return $this->certificates;
    }

    public function toXML(DOMNode $parentElement = NULL)
    {
        if ($parentElement === NULL) {
            $document = new DOMDocument();
            $parentElement = $document;
        } else {
            $document = $parentElement->ownerDocument;
        }

        $root = $document->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:' . 'Assertion');
        $parentElement->appendChild($root);

        /* Ugly hack to add another namespace declaration to the root element. */
        $root->setAttributeNS('urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:tmp', 'tmp');
        $root->removeAttributeNS('urn:oasis:names:tc:SAML:2.0:protocol', 'tmp');
        $root->setAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'xsi:tmp', 'tmp');
        $root->removeAttributeNS('http://www.w3.org/2001/XMLSchema-instance', 'tmp');
        $root->setAttributeNS('http://www.w3.org/2001/XMLSchema', 'xs:tmp', 'tmp');
        $root->removeAttributeNS('http://www.w3.org/2001/XMLSchema', 'tmp');

        $root->setAttribute('ID', $this->id);
        $root->setAttribute('Version', '2.0');
        $root->setAttribute('IssueInstant', gmdate('Y-m-d\TH:i:s\Z', $this->issueInstant));

        $issuer = Utilities::addString($root, 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Issuer', $this->issuer);

        $this->addSubject($root);
        $this->addConditions($root);
        $this->addAuthnStatement($root);
        if ($this->requiredEncAttributes == FALSE) {
            $this->addAttributeStatement($root);
        } else {
            $this->addEncryptedAttributeStatement($root);
        }

        if ($this->signatureKey !== NULL) {
            Utilities::insertSignature($this->signatureKey, $this->certificates, $root, $issuer->nextSibling);
        }

        return $root;
    }

    private function addSubject(DOMElement $root)
    {
        if ($this->nameId === NULL && $this->encryptedNameId === NULL) {
            /* We don't have anything to create a Subject node for. */

            return;
        }

        $subject = $root->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Subject');
        $root->appendChild($subject);

        if ($this->encryptedNameId === NULL) {
            Utilities::addNameId($subject, $this->nameId);
        } else {
            $eid = $subject->ownerDocument->createElementNS('urn:oasis:names:tc:SAML:2.0:assertion', 'saml:' . 'EncryptedID');
            $subject->appendChild($eid);
            $eid->appendChild($subject->ownerDocument->importNode($this->encryptedNameId, TRUE));
        }

        foreach ($this->SubjectConfirmation as $sc) {
            $sc->toXML($subject);
        }
    }


}
