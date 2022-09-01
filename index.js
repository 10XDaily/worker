import { Router } from 'itty-router'

// Create a new router
const router = Router()

// Basic Auth protection of private pages https://developers.cloudflare.com/workers/examples/basic-auth/
// Cloudflare Secret Environment Variables (https://dash.cloudflare.com/3f3a7e7d6b29f0389b841af63623becd/workers/services/view/worker/production/settings/bindings)
const BASIC_USER = BASIC_USER_SECRET;
const BASIC_PASS = BASIC_PASS_SECRET;

router.get("/logout", () => {
  console.log("logout logs");
  // Invalidate the "Authorization" header by returning a HTTP 401.
  // We do not send a "WWW-Authenticate" header, as this would trigger
  // a popup in the browser, immediately asking for credentials again.
  return new Response('Logged out.', { status: 401 });
})

/*
Our index route, a simple hello world. No login required.
*/
router.get("/", () => {
  console.log("index logs");
  return new Response("10X Your Day!");
})

// Cloudflare Secret Environment Variables (https://dash.cloudflare.com/3f3a7e7d6b29f0389b841af63623becd/workers/services/view/worker/production/settings/bindings)
const X_API_KEY = XANO_API_KEY; // Key for accessing Xano endpoints - Generated in GetResponse settings (https://app.getresponse.com/api)
const GR_API_KEY = GETRESPONSE_API_KEY; // Key for accessing GetResponse api - Generated in GetResponse settings (https://app.getresponse.com/api

const GR_API = 'https://api.getresponse.com/v3/';
const GR_API_NEWSLETTERS = "newsletters" // https://apireference.getresponse.com/#operation/createNewsletter

const X_API = 'https://x8ki-letl-twmt.n7.xano.io/api:xhF9IGoC/';
const X_API_LEXPAD = "lexpad" // https://x8ki-letl-twmt.n7.xano.io/apidoc:xhF9IGoC/#/lexpad
const X_API_FEEDLY = "feedly" // https://x8ki-letl-twmt.n7.xano.io/api:xhF9IGoC/feedly

/*
The newletter route is for creating and sending the 10X Daily email newsletter via GetResponse
*/
router.get("/newsletter", async request => {
  console.log("newsletter logs");
  
  const { protocol, pathname } = new URL(request.url);

  // In the case of a Basic authentication, the exchange MUST happen over an HTTPS (TLS) connection to be secure.
  if ('https:' !== protocol || 'https' !== request.headers.get('x-forwarded-proto')) {
    throw new BadRequestException('Please use a HTTPS connection.');
  }
  
  // The "Authorization" header is sent when authenticated.
  if (request.headers.has('Authorization')) {
    // Throws exception when authorization fails.
    const { user, pass } = basicAuthentication(request);
    verifyCredentials(user, pass);

    // Only returns this response when no exception is thrown.
  
    const html_email = await sendNewsletter();
    console.log(html_email);
    
console.log("Test AFTER sendNewsetter");

    let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
    let html_content = '<h1>Success!!!</h1>';
    // html_content += `<p>... add more HTML to confirm the email sent successfully</p>`; // TODO

    let html = `
  <!DOCTYPE html>
  <head>
    <title>Newsletter: Send</title>
  </head>
  <body>
    <style>${html_style}</style>
    <div id="container">
    ${html_content}
    </div>
  </body>`;

    return new Response(html, {
      headers: {
        'content-type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-store',
      },
    });
  }
  
  // Not authenticated.
  return new Response('You need to login.', {
    status: 401,
    headers: {
      // Prompts the user for credentials.
      'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"',
    },
  });
})

/*
The /feedly route is for caching feedly topic data before sending the 10X Daily email newsletter via the /newsletter route
*/
router.get("/feedly", async request => {
  console.log("feedly logs");
  
  const { protocol, pathname } = new URL(request.url);

  // In the case of a Basic authentication, the exchange MUST happen over an HTTPS (TLS) connection to be secure.
  if ('https:' !== protocol || 'https' !== request.headers.get('x-forwarded-proto')) {
    throw new BadRequestException('Please use a HTTPS connection.');
  }
  
  // The "Authorization" header is sent when authenticated.
  if (request.headers.has('Authorization')) {
    // Throws exception when authorization fails.
    const { user, pass } = basicAuthentication(request);
    verifyCredentials(user, pass);

    // Only returns this response when no exception is thrown.
  
    const feedly_cache = await cacheFeedly();
    console.log(feedly_cache);
    
console.log("Test AFTER cacheFeedly");

    let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
    let html_content = '<h1>Feedly cached!!!</h1>';
    // html_content += `<p>... add more HTML to confirm the email sent successfully</p>`; // TODO

    let html = `
  <!DOCTYPE html>
  <head>
    <title>Feedly: Cached</title>
  </head>
  <body>
    <style>${html_style}</style>
    <div id="container">
    ${html_content}
    </div>
  </body>`;

    return new Response(html, {
      headers: {
        'content-type': 'text/html;charset=UTF-8',
        'Cache-Control': 'no-store',
      },
    });
  }
  
  // Not authenticated.
  return new Response('You need to login.', {
    status: 401,
    headers: {
      // Prompts the user for credentials.
      'WWW-Authenticate': 'Basic realm="my scope", charset="UTF-8"',
    },
  });
})

/*
Experimenting with Content shortlinks and Referral IDs
Default Referral = 10X Daily
Content Referral = Content Creator (e.g. blog post publishers)
Traffic Referral = Traffic Source (e.g. 10x daily users)
*/
const default_ref_id = '123' // default Referral ID

// Content ID slugs
const content = {
  '1': {
    'content_ref_id': default_ref_id // default Referral ID for this content
  },
  '2': {
    'content_ref_id': '456' // custom Referral ID for this content creator
  }
}

// Redirect to landingpage URL... for now everything will redirect here.
const redirect_to = 'https://www.10x.day'

/*
Extract the short Content ID from URL then redirect to a landing page

Try visit /1 and see the response for Default Referral ID
Try visit /2 and see the response for Content Referral ID
Try visit /2?ref=789 and see the response for Traffic Referral ID
*/
router.get("/:slug", ({ params, query }) => {
  let content_id = params.slug;
  let content_data = content[content_id];
  
  if(!content_data) {
      return new Response('Content ID not found.', {
      status: 404,
    });
  } else {
    let content_ref = content_data.content_ref_id;
    let traffic_ref = '';
    
    // Get traffic Referral ID from query parameters
    traffic_ref = query.ref || query.ref_id || '';
    let has_traffic_ref = traffic_ref ? true : false; 
    
    let referral = content_ref;
    
    // Traffic referred by someone else e.g. worker.10X.day/2?ref=789
    if(has_traffic_ref) {
      referral = traffic_ref;
    }
    
    let referral_query_string = `ref_id=${referral}&`;
        
    let link = `${redirect_to}?${referral_query_string}traffic_ref=${traffic_ref}&utm_content=${content_id}`;
    console.log(link);
    
    return new Response(null, {
      headers: { Location: link },
      status: 302,
    });
  };
})


/**
 * Throws exception on verification failure.
 * @param {string} user
 * @param {string} pass
 * @throws {UnauthorizedException}
 */
function verifyCredentials(user, pass) {
  if (BASIC_USER !== user) {
    throw new UnauthorizedException('Invalid credentials.');
  }

  if (BASIC_PASS !== pass) {
    throw new UnauthorizedException('Invalid credentials.');
  }
}

/**
 * Parse HTTP Basic Authorization value.
 * @param {Request} request
 * @throws {BadRequestException}
 * @returns {{ user: string, pass: string }}
 */
function basicAuthentication(request) {
  const Authorization = request.headers.get('Authorization');

  const [scheme, encoded] = Authorization.split(' ');

  // The Authorization header must start with Basic, followed by a space.
  if (!encoded || scheme !== 'Basic') {
    throw new BadRequestException('Malformed authorization header.');
  }

  // Decodes the base64 value and performs unicode normalization.
  // @see https://datatracker.ietf.org/doc/html/rfc7613#section-3.3.2 (and #section-4.2.2)
  // @see https://dev.mozilla.org/docs/Web/JavaScript/Reference/Global_Objects/String/normalize
  const buffer = Uint8Array.from(atob(encoded), character => character.charCodeAt(0));
  const decoded = new TextDecoder().decode(buffer).normalize();

  // The username & password are split by the first colon.
  //=> example: "username:password"
  const index = decoded.indexOf(':');

  // The user & password are split by the first colon and MUST NOT contain control characters.
  // @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
  if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
    throw new BadRequestException('Invalid authorization value.');
  }

  return {
    user: decoded.substring(0, index),
    pass: decoded.substring(index + 1),
  };
}

function UnauthorizedException(reason) {
  this.status = 401;
  this.statusText = 'Unauthorized';
  this.reason = reason;
}

function BadRequestException(reason) {
  this.status = 400;
  this.statusText = 'Bad Request';
  this.reason = reason;
}

/**
* Feedly topics cached in Xano
* Triggered via /feedly URL, or via Cloudflare Worker CRON (4:30am daily)
**/
async function cacheFeedly() {
  console.log('cacheFeedly start');
  return new Promise(async function (resolve) {
    let today = new Date(); // Cloudflare workers freeze time, see https://developers.cloudflare.com/workers/learning/security-model/
    let endpoint = X_API + X_API_FEEDLY;
    let json_body = {};
    
    const init = {
      headers: {
        'content-type': 'application/json;charset=UTF-8',
        'X-Time-Zone': 'Australia/Sydney', // the default timezone in response data is UTC (if I remove this header)
        'X-Auth-Token': X_API_KEY
      },
      body: JSON.stringify(json_body),
      method: 'POST'
    };
console.log("Test AFTER init");
console.log(init);

    const response = await fetch(endpoint, init);
console.log("Test AFTER fetch");
    const content = await response.json();
console.log("Test AFTER response");
    
    resolve(content);
  });
}

/**
* Newsletter sent via GetResponse API. 
* Triggered via /newsletter URL, or via Cloudflare Worker CRON (5am daily)
**/
async function sendNewsletter() {
  console.log('sendNewsletter start');
  return new Promise(async function (resolve) {
    let today = new Date(); // Cloudflare workers freeze time, see https://developers.cloudflare.com/workers/learning/security-model/
    let endpoint = `${GR_API}${GR_API_NEWSLETTERS}`;
    let email_json = {
      "content": {
        "html": `
<!--[if lt IE 8]>
<style>
.container375{
  width: 375px;
  font-size:16px;
}
</style>
<![endif]-->

<div>
  <!--[if gte mso 9]><table width="375" cellpadding="0" cellspacing="0"><tr><td><![endif]-->
  <table class="container375" width="100%" style="max-width:375px;margin: 0;" cellpadding="0" cellspacing="0" border="0">
    <tr>
      <td width="100%" style="text-align:left;">
      

<b>“Knowledge is Power ⚡ Money is Freedom”</b>
<br>— 10X Daily

<br>
<br><center style="text-align:center;">•&nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;•</center>
<br>
<br>

📈 <b>Daily Stats</b>        
<br>
<br><b>Status:</b>
{{LOOP "user" "user_attribute_name" "user_attribute_value"}}
  {{IF "((user_attribute_name STRING_EQ 'active') LOGIC_AND (user_attribute_value NUMBER_EQ '1'))"}}
    Active
  {{ENDIF}}
  {{IF "((user_attribute_name STRING_EQ 'active') LOGIC_AND (user_attribute_value NUMBER_EQ '0'))"}}
    Inactive
  {{ENDIF}}
{{ENDLOOP}}

<br>
<br><center style="text-align:center;">•&nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;•</center>
<br>
<br>

🔥 <b>Daily News</b>
<br>
{{LOOP "feedly" "topic_name" "articles"}}
  <br><b>{{TOPIC "topic_name"}}</b>
  {{LOOP "articles" "article"}}
    <br><b><a href="{{LINK "article" "canonicalUrl"}}">
        {{TOPIC "article" "title"}}
      </a></b>
    <br>
  {{ENDLOOP}}
  
<br><center style="text-align:center;">•&nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;•&nbsp;&nbsp;&nbsp;•</center>
<br>

{{ENDLOOP}}

<br>{{RANDOM \`Hi\` \`Hello\` \`Hey\`}} <b>[[firstname]]</b>, this email is sent daily.
<br>Date: {{DATE \`YEAR-MONTH-DAY\`}}
<br>Time: {{DATE \`HOUR:MINUTE:SECOND\`}}
<br>Campaign ID: {{CONTACT \`campaign_id\`}}
<br>Message ID: {{CONTACT \`message_id\`}}
<br>Subscriber ID: {{CONTACT \`subscriber_id\`}}

      </td>
    </tr>
  </table>
  <!--[if gte mso 9]></td></tr></table><![endif]-->
</div>
`,
       "plain": `
“Knowledge is Power ⚡ Money is Freedom”
— 10X Daily

                                 •   •   •   •   • 

📈 Daily Stats
Status: 

                                 •   •   •   •   • 

🔥 Daily News

CRYPTO


                                 •   •   •   •   • 

{{RANDOM \`Hi\` \`Hello\` \`Hey\`}} [[firstname]], this email is sent daily.
Date: {{DATE \`YEAR-MONTH-DAY\`}}
Time: {{DATE \`HOUR:MINUTE:SECOND\`}}
Campaign ID: {{CONTACT \`campaign_id\`}}
Message ID: {{CONTACT \`message_id\`}}
Subscriber ID: {{CONTACT \`subscriber_id\`}}

`// TODO - dynamic plaintext version of the HTML email? (strip HTML)
      },
      "flags": [
        "openrate",
        "clicktrack"
        // "google_analytics" // requires higher paid plan. Adds UTM tracking on links in email, to be tracked on our Website
      ],
      "name": today.toISOString() + ' 10X DAILY', // TODO make timezone aware (e.g. Australia/Sydney). Note that .toISOString() always returns a timestamp in UTC
      "type": "broadcast", // draft or broadcast
      "editor": "custom",
      "subject": '10X [[firstname mode="uc"]] ⚡ {{DATE "DAY_ORDINATED MONTH_NAME YEAR"}}',
      "fromField": {
        "fromFieldId": "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "replyTo": {
        "fromFieldId": "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "campaign": {
        "campaignId": "LCJtj" // "Q1Oz0" // "10X Daily" subscriber list // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns
      },
  //    "sendOn": "2022-08-13T05:39:55+10:00", // omitted to send message immediately i.e. the manual trigger or 5am CRON trigger will send the message
  //     "attachments": [
  //       {
  //         "fileName": "some_file.jpg",
  //         "content": "sdfadsfetsdjfdskafdsaf==",
  //         "mimeType": "image/jpeg"
  //       }
  //     ], // No attachements needed. 400kb max combined size if needed in the future.
      "sendSettings": {
        "selectedCampaigns": ["LCJtj"], // ["Q1Oz0"], // "10X Daily" subscriber list
        "selectedSegments": [], // TODO add Custom Field "UTC Offset Timezone" with 25 values "UTC -12"... "UTC 0" ... "UTC +12". Use for 5am email delivery.
        "selectedSuppressions": [],
        "excludedCampaigns": [],
        "excludedSegments": [],
        "selectedContacts": ["V5p8EtA"], // ["VohAb0F"], // Contact ID for email subscriber "test+5@10x.day" // {campaignId} = Q1Oz0 // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns/Q1Oz0/contacts
        "timeTravel": "false", // requires higher paid plan. Instead we will use a Segment, and user defined Custom Field "UTC Offset Timezone".
        "perfectTiming": "false",
        "externalLexpad": {
           "dataSourceUrl": X_API + X_API_LEXPAD,
           "dataSourceToken": X_API_KEY
        }
      }
    }

console.log("Test AFTER email_json");

    const init = {
      headers: {
        'content-type': 'application/json;charset=UTF-8',
        'X-Time-Zone': 'Australia/Sydney', // the default timezone in response data is UTC (if I remove this header)
        'X-Auth-Token': 'api-key ' + GR_API_KEY
      },
      body: JSON.stringify(email_json),
      method: 'POST'
    };
console.log("Test AFTER init");
console.log(init);

    const response = await fetch(endpoint, init);
console.log("Test AFTER fetch");
    const content = await response.json();
console.log("Test AFTER response");
    
    resolve(content);
  });
}

/*
This is the last route we define, it will match anything that hasn't hit a route we've defined
above, therefore it's useful as a 404 (and avoids us hitting worker exceptions, so make sure to include it!).

Visit any page that doesn't exist (e.g. /foobar) to see it in action.
*/
router.all("*", () => new Response("404, not found!", { status: 404 }))

/*
This snippet ties our worker to the router we deifned above, all incoming requests
are passed to the router where your routes are called and the response is sent.
*/
addEventListener('fetch', (e) => {
  e.respondWith(router.handle(e.request).catch(err => {
      const message = err.reason || err.stack || 'Unknown Error';

      return new Response(message, {
        status: err.status || 500,
        statusText: err.statusText || null,
        headers: {
          'Content-Type': 'text/plain;charset=UTF-8',
          // Disables caching by default.
          'Cache-Control': 'no-store',
          // Returns the "Content-Length" header for HTTP HEAD requests.
          'Content-Length': message.length,
        },
      });
    })
  )
})

// https://developers.cloudflare.com/workers/examples/cron-trigger/
// https://developers.cloudflare.com/workers/platform/cron-triggers/
addEventListener('scheduled', event => {
  event.waitUntil(triggerEvent(event.scheduledTime));
});

async function triggerEvent(scheduledTime) {
  console.log('cron logs start');
  const cron_feedly = await cacheFeedly();
  console.log(cron_feedly);
  const cron_email = await sendNewsletter();
  console.log(cron_email);
  console.log('cron logs end'); 
}
