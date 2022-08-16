import { Router } from 'itty-router'

// Create a new router
const router = Router()

/*
Our index route, a simple hello world.
*/
router.get("/", () => {
  console.log("index logs");
  return new Response("10X Your Day!");
})

/*
The newletter route is for creating and sending the 10X Daily email newsletter via GetResponse
*/
const GR_API_KEY = GETRESPONSE_API_KEY; // Cloudflare Secret Variable
const GR_API = 'https://api.getresponse.com/v3/';
const GR_API_NEWSLETTERS = "newsletters" // https://apireference.getresponse.com/#operation/createNewsletter

router.get("/newsletter", async request => {
  console.log("newsletter logs");
  
  let today = new Date(); // Cloudflare workers freeze time, see https://developers.cloudflare.com/workers/learning/security-model/
  let endpoint = `${GR_API}${GR_API_NEWSLETTERS}`;
  let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
  let html_content = '<h1>Success</h1>';
  
  let email_json = {
    "content": {
      "html": `
<p>
“Knowledge is Power ⚡ Money is Freedom”
<br>— 10X Daily
</p>
<p>
                                   •   •   •   •   • 
</p>
<p>
📈 Daily Stats
<br>Status: {{IF "(active IS_DEFINED)"}}Active{{ELSE}}Inactive{{ENDIF}}
<br>Status3: {{IF "(active STRING_EQI 'true')"}}Active{{ELSE}}Inactive{{ENDIF}}
<br>Status4: {{IF "(active NUMBER_GT '0')"}}Active{{ELSE}}Inactive{{ENDIF}}
<br>{{TOPIC "name"}}
</p>
<p>
                                   •   •   •   •   • 
</p>
<p>
{{RANDOM \`Hi\` \`Hello\` \`Hey\`}} <b>[[firstname]]</b>, this email is sent daily.
<br>Date: {{DATE \`YEAR-MONTH-DAY\`}}
<br>Time: {{DATE \`HOUR:MINUTE:SECOND\`}}
<br>Campaign ID: {{CONTACT \`campaign_id\`}}
<br>Message ID: {{CONTACT \`message_id\`}}
<br>Subscriber ID: {{CONTACT \`subscriber_id\`}}
</p>
`,
      "plain": `
“Knowledge is Power ⚡ Money is Freedom”
— 10X Daily

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
      "fromFieldId": "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
    },
    "replyTo": {
      "fromFieldId": "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
    },
    "campaign": {
      "campaignId": "Q1Oz0" // "10X Daily" subscriber list // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns
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
      "selectedCampaigns": ["Q1Oz0"], // "10X Daily" subscriber list
      "selectedSegments": [], // TODO add Custom Field "UTC Offset Timezone" with 25 values "UTC -12"... "UTC 0" ... "UTC +12". Use for 5am email delivery.
      "selectedSuppressions": [],
      "excludedCampaigns": [],
      "excludedSegments": [],
      "selectedContacts": ["VohAb0F"], // Contact ID for email subscriber "test+5@10x.day" // {campaignId} = Q1Oz0 // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns/Q1Oz0/contacts
      "timeTravel": "false", // requires higher paid plan. Instead we will use a Segment, and user defined Custom Field "UTC Offset Timezone".
      "perfectTiming": "false",
      "externalLexpad": {
         "dataSourceUrl": "https://x8ki-letl-twmt.n7.xano.io/api:xhF9IGoC/lexpad",
         "dataSourceToken": GR_API_KEY
      }
    }
  }
  
  const init = {
    headers: {
      'content-type': 'application/json;charset=UTF-8',
      'X-Time-Zone': 'Australia/Sydney', // the default timezone in response data is UTC (if I remove this header)
      'X-Auth-Token': 'api-key ' + GR_API_KEY
    },
    body: JSON.stringify(email_json),
    method: 'POST'
  };

  const response = await fetch(endpoint, init);
  const content = await response.json();
  
  console.log(content);

//   html_content += `<p>... add more HTML to confirm the email sent successfully</p>`; // TODO

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
  e.respondWith(router.handle(e.request))
})
