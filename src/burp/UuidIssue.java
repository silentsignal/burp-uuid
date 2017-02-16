package burp;

import java.net.URL;
import java.util.UUID;

public class UuidIssue implements IScanIssue {
	private final IHttpRequestResponse[] httpMessages;
	private final URL url;
	private final UUID uuid;
	private final boolean isV1or2;

	public UuidIssue(IHttpRequestResponse baseRequestResponse,
			URL url, UUID uuid) throws IllegalArgumentException {
		httpMessages = new IHttpRequestResponse[] { baseRequestResponse };
		this.url = url;
		this.uuid = uuid;
		isV1or2 = uuid.version() < 3;
	}

	@Override public String getIssueName() {
		return "Version " + uuid.version() + " UUID in HTTP request";
	}

	@Override public String getIssueDetail() {
		int v = uuid.version();
		final String prefix = "The request contains the version " + v +
			" UUID <b>" + uuid + "</b> which is ";
		switch (v) {
			case 1:
				return prefix + "generated from <ul>" +
					"<li>the timestamp <b>" + uuid.timestamp() + "</b>,</li>" +
					"<li>the clock sequence <b>" + uuid.clockSequence() + "</b> and</li>" +
					"<li>the node (MAC address) <b>" + Long.toHexString(uuid.node()) + "</b>.</li>" +
					"</ul>This means that it's not fit for authorization purposes, as " +
					"it can be easily regenerated once the node and the approximate time is known.";
			case 2:
				return prefix + "generated using the DCE algorithm from a " +
					"timestamp, a clock sequence, a domain ID and a node value. " +
					"This means that it's not fit for authorization purposes, as " +
					"it can be easily regenerated once the node and the approximate time is known.";
			case 3:
				return prefix + "derived from a name using MD5.";
			case 4:
				return prefix + "randomly generated, although its entropy should be checked.";
			case 5:
				return prefix + "derived from a name using SHA-1.";
			default:
				return prefix + "generated/derived from an unknown data source.";
		}
	}

	public final static String REMEDIATION = "Use version 4 (random) UUIDs";

	@Override public String getConfidence() { return "Firm"; }
	@Override public IHttpRequestResponse[] getHttpMessages() { return httpMessages; }
	@Override public IHttpService getHttpService() { return httpMessages[0].getHttpService(); }
	@Override public String getIssueBackground() { return null; }
	@Override public int getIssueType() { return 0x08000000; }
	@Override public String getRemediationBackground() { return null; }
	@Override public String getRemediationDetail() { return isV1or2 ? REMEDIATION : null; }
	@Override public String getSeverity() { return isV1or2 ? "Medium" : "Information"; }
	@Override public URL getUrl() { return url; }
}