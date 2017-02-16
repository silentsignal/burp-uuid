package burp;

import java.net.URL;
import java.util.*;
import java.util.regex.*;

public class BurpExtender implements IBurpExtender, IScannerCheck
{
	private IExtensionHelpers helpers;
	private IBurpExtenderCallbacks callbacks;
	private final static Pattern uuidPattern = Pattern.compile(
			"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
			Pattern.CASE_INSENSITIVE);

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		callbacks.setExtensionName("UUID issues");
		callbacks.registerScannerCheck(this);
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();
	}

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseMsg) {
		List<IScanIssue> issues = new ArrayList<>();
		String request = helpers.bytesToString(baseMsg.getRequest());
		Matcher m = uuidPattern.matcher(request);
		URL url = null;
		while (m.find()) {
			if (url == null) {
				url = helpers.analyzeRequest(baseMsg.getHttpService(),
						baseMsg.getRequest()).getUrl();
			}
			UUID u;
			try {
				u = UUID.fromString(m.group());
			} catch (IllegalArgumentException iae) {
				// ignore invalid UUIDs
				continue;
			}
			IHttpRequestResponse msg = callbacks.applyMarkers(baseMsg,
					Collections.singletonList(new int[] { m.start(), m.end() }), null);
			issues.add(new UuidIssue(msg, url, u));
		}
		return issues;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseMsg,
			IScannerInsertionPoint insertionPoint) {
		return null;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
		return -1;
	}
}
