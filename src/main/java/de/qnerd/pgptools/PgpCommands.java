package de.qnerd.pgptools;

import java.io.IOException;
import java.security.NoSuchProviderException;

import org.bouncycastle.openpgp.PGPException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;


@ShellComponent
public class PgpCommands {
	
	@Autowired
	private PgpService pgpService;

	@Value("${application.name}")
	private String applicationName;

	@Value("${build.version}")
	private String buildVersion;

	@Value("${build.timestamp}")
	private String buildTimestamp;
	
	@ShellMethod("shows the build version")
    public String version() {
      return buildVersion;
    }
	
	 
	@ShellMethod("encrypt")
	public void encrypt(String keyfile, String datafile) throws IOException, NoSuchProviderException, PGPException {
		pgpService.encrypt(keyfile,datafile);
		
	}
	
}
