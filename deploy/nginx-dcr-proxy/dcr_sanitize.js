async function proxyDcrRegistration(r) {
    let requestBody = r.requestText || "";

    if (r.method === "POST" && requestBody.length > 0) {
        let payload;
        try {
            payload = JSON.parse(requestBody);
        } catch (error) {
            r.return(400, "Invalid JSON body");
            return;
        }

        if (Object.prototype.hasOwnProperty.call(payload, "registration_url")) {
            delete payload.registration_url;
            requestBody = JSON.stringify(payload);
        }
    }

    const subrequestPath = r.variables.args
        ? `/_keycloak_dcr_upstream?${r.variables.args}`
        : "/_keycloak_dcr_upstream";

    let reply;
    try {
        const options = { method: r.method };
        if (r.method === "POST" || r.method === "PUT" || r.method === "PATCH") {
            options.body = requestBody;
        }
        reply = await r.subrequest(subrequestPath, options);
    } catch (error) {
        r.error(`DCR proxy subrequest failed: ${error}`);
        r.return(502, "Bad Gateway");
        return;
    }

    if (reply.headersOut["Content-Type"]) {
        r.headersOut["Content-Type"] = reply.headersOut["Content-Type"];
    }
    if (reply.headersOut.Location) {
        r.headersOut.Location = reply.headersOut.Location;
    }
    if (reply.headersOut["Cache-Control"]) {
        r.headersOut["Cache-Control"] = reply.headersOut["Cache-Control"];
    }
    if (reply.headersOut.Pragma) {
        r.headersOut.Pragma = reply.headersOut.Pragma;
    }

    r.return(reply.status, reply.responseText);
}

export default { proxyDcrRegistration };
