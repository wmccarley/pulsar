package org.apache.pulsar.common.util.keystoretls;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.security.auth.x500.X500Principal;


public class TogglingKeyManager  extends X509ExtendedKeyManager {
	private static final String DEFAULT_ALIAS = "default";
	
	private final X509ExtendedKeyManager keyManager;
	
	public TogglingKeyManager(X509ExtendedKeyManager keyManager) {
		this.keyManager = keyManager;
	}
	

	@Override
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		throw new UnsupportedOperationException(); // we don't use client mode
	}
	
	@Override
	public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
		throw new UnsupportedOperationException(); // as above
	}
	
	@Override
	public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
		throw new UnsupportedOperationException(); // as above
	}
	
	@Override
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		return keyManager.getServerAliases(keyType, issuers);
	}

	@Override
	public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
		throw new UnsupportedOperationException(); // Netty does not use SSLSocket
	}
	
	@Override
	public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
		try {
			Certificate[] peerChain = engine.getHandshakeSession().getPeerCertificates();
			
			X500Principal issuingPrincipal = ((X509Certificate) peerChain[0]).getIssuerX500Principal();
			
			String commonName = new LdapName(issuingPrincipal.getName()).getRdns().stream().filter(i -> i.getType().equalsIgnoreCase("CN")).findFirst().get().getValue().toString();
			
			return commonName;
		} catch (SSLPeerUnverifiedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidNameException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return DEFAULT_ALIAS;
		
	}

	@Override
	public X509Certificate[] getCertificateChain(String alias) {
		return keyManager.getCertificateChain(alias);
	}


	@Override
	public PrivateKey getPrivateKey(String alias) {
		return keyManager.getPrivateKey(alias);
	}

}
