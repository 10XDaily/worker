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
const X_API_ENTRIES = "entries" // https://x8ki-letl-twmt.n7.xano.io/api:xhF9IGoC/entries
const X_API_NEWS = "news" // https://x8ki-letl-twmt.n7.xano.io/api:xhF9IGoC/news

/*
The newsemail route is for creating and sending the 10X News daily email newsletter via GetResponse
*/
router.get("/newsemail", async request => {
  console.log("newsemail logs");
  
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
  
    const html_email = await sendNewsemail();
    console.log(html_email);
    
console.log("Test AFTER sendNewsemail");

    let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
    let html_content = '<h1>Success!!!</h1>';
    // html_content += `<p>... add more HTML to confirm the email sent successfully</p>`; // TODO

    let html = `
  <!DOCTYPE html>
  <head>
    <title>Newsemail: Send</title>
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
The dealsemail route is for creating and sending the 10X Deals daily email newsletter via GetResponse
*/
router.get("/dealsemail", async request => {
  console.log("dealsemail logs");
  
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
  
    const html_email = await sendDealsemail();
    console.log(html_email);
    
console.log("Test AFTER sendDealsemail");

    let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
    let html_content = '<h1>Success!!!</h1>';
    // html_content += `<p>... add more HTML to confirm the email sent successfully</p>`; // TODO

    let html = `
  <!DOCTYPE html>
  <head>
    <title>Dealsemail: Send</title>
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
The statsemail route is for creating and sending the 10X Stats daily email newsletter via GetResponse
*/
router.get("/statsemail", async request => {
  console.log("statsemail logs");
  
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
  
    const html_email = await sendStatsemail();
    console.log(html_email);
    
console.log("Test AFTER sendStatsemail");

    let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
    let html_content = '<h1>Success!!!</h1>';
    // html_content += `<p>... add more HTML to confirm the email sent successfully</p>`; // TODO

    let html = `
  <!DOCTYPE html>
  <head>
    <title>Statsemail: Send</title>
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
The /entries route is for caching daily feedly stream data...
Then call /news route to filter down to the Top 10 per topic...
Then send the 10X Daily email newsletter via the /newsletter route
*/
router.get("/entries", async request => {
  console.log("entries logs");
  
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
  
    const entries_cache = await cacheEntries();
    console.log(entries_cache);
    
console.log("Test AFTER cacheEntries");

    let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
    let html_content = '<h1>Entries cached!!!</h1>';
    // html_content += `<p>... add more HTML to confirm the email sent successfully</p>`; // TODO

    let html = `
  <!DOCTYPE html>
  <head>
    <title>Entries: Cached</title>
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
Before calling /news, first call /entries to populate the Xano database with the daily feedly stream data...
Then call /news route to filter down to the Top 10 per topic...
Then send the 10X Daily email newsletter via the /newsletter route
*/
router.get("/news", async request => {
  console.log("news logs");
  
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
  
    const news_cache = await cacheNews();
    console.log(news_cache);
    
console.log("Test AFTER cacheNews");

    let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
    let html_content = '<h1>News cached!!!</h1>';
    // html_content += `<p>... add more HTML to confirm the email sent successfully</p>`; // TODO

    let html = `
  <!DOCTYPE html>
  <head>
    <title>News: Cached</title>
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
* Streams feedly entries into Xano
* Triggered via /entries URL, or via Cloudflare Worker CRON
**/
async function cacheEntries() {
  console.log('cacheEntries start');
  return new Promise(async function (resolve) {
    let today = new Date(); // Cloudflare workers freeze time, see https://developers.cloudflare.com/workers/learning/security-model/
    let endpoint = X_API + X_API_ENTRIES;
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
* Extracts the daily Top 10 (per topic) entries in Xano, and copies them to the News table.
* Triggered via /news URL, or via Cloudflare Worker CRON
* NOTE: You must trigger /entries FIRST (to populate the Entries table), and wait for it to finish before triggering /news
* REMEMBER: The /news endpoint also clears all record in the Entries table after it finishes
**/
async function cacheNews() {
  console.log('cacheNews start');
  return new Promise(async function (resolve) {
    let today = new Date(); // Cloudflare workers freeze time, see https://developers.cloudflare.com/workers/learning/security-model/
    let endpoint = X_API + X_API_NEWS;
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
* News sent via GetResponse API. 
* Triggered via /newsemail URL, or via Cloudflare Worker CRON
**/
async function sendNewsemail() {
  console.log('sendNewsemail start');
  return new Promise(async function (resolve) {
    let today = new Date(); // Cloudflare workers freeze time, see https://developers.cloudflare.com/workers/learning/security-model/
    let emojis = ["😀","😃","😄","😁","😆","😅","😂","🤣","😊","😇","🙂","🙃","😉","😌","😍","🥰","😘","😗","😙","😚","😋","😛","😝","😜","🤪","🤨","🧐","🤓","😎","🤩","🥳","😏","😒","😞","😔","😟","😕","🙁","☹️","😣","😖","😫","😩","🥺","😢","😭","😤","😠","😡","🤬","🤯","😳","🥵","🥶","😱","😨","😰","😥","😓","🤗","🤔","🤭","🤫","🤥","😶","😐","😑","😬","🙄","😯","😦","😧","😮","😲","🥱","😴","🤤","😪","😵","🤐","🥴","🤢","🤮","🤧","😷","🤒","🤕","🤑","🤠","😈","👿","👹","👺","🤡","💩","👻","👽","👾","🤖","🎃"];
    let emoji = emojis[Math.floor(Math.random()*emojis.length)];
    let endpoint = `${GR_API}${GR_API_NEWSLETTERS}`;
    let email_json = {
      "content": {
        "html": `
<table cellpadding="0" cellspacing="0" role="presentation" style="background-color:#f5f7fb;padding:4%;" width="100%"><tbody><tr><td align="center">
  <table cellpadding="0" cellspacing="0" role="presentation" style="max-width:500px" width="100%"><tbody><tr><td>
    <table align="center" cellpadding="0" cellspacing="0" role="presentation"><tbody><tr style="background-color:#f5f7fb"><td style="padding:0">
      <table align="center" cellpadding="0" cellspacing="0" role="presentation">
        <tbody>
          <tr style="background-color:#f5f7fb">
            <td>
	    
	      <h1 style="margin:0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🤘 Daily Quote
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:center;">
			<p style="margin:3% 0 0 0;color:#29303e;font-weight:900;font-size:1.5rem;font-family:sans-serif;line-height:1.5;">
                          “Knowledge is Power ⚡ Money is Freedom” <span style="color:#677489;">—&nbsp;10X&nbsp;Daily</span>
                        </p>
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <a href="https://twitter.com/intent/tweet?text=%E2%80%9CKnowledge%20is%20Power%20%E2%9A%A1%20Money%20is%20Freedom%E2%80%9D%20%E2%80%94%2010X%20Daily&url=https%3A%2F%2F10x.day&hashtags=10X&via=10XDaily" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
	      
	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        ⚡ Daily Action
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:center;">
			<p style="margin:0;"><span style="color:#29303e;font-weight:700;font-size:1.2rem;font-family:sans-serif;line-height:1.3;">Poll: Do you have a business?</span></p>
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;margin:4% 0 0 0;padding:4% 0;line-height:1.5;font-weight:700;background-color:#fff;color:#15c;border:2px solid #15c;border-radius:4px;">
                            Nope, not interested
                          </a>
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;margin:4% 0 0 0;padding:4% 0;line-height:1.5;font-weight:700;background-color:#fff;color:#15c;border:2px solid #15c;border-radius:4px;">
                            Thinking up ideas
                          </a>
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;margin:4% 0 0 0;padding:4% 0;line-height:1.5;font-weight:700;background-color:#fff;color:#15c;border:2px solid #15c;border-radius:4px;">
                            In development (Pre-launch)
                          </a>
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;margin:4% 0 0 0;padding:4% 0;line-height:1.5;font-weight:700;background-color:#fff;color:#15c;border:2px solid #15c;border-radius:4px;">
                            Launched (Pre-revenue)
                          </a>
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;margin:4% 0 0 0;padding:4% 0;line-height:1.5;font-weight:700;background-color:#fff;color:#15c;border:2px solid #15c;border-radius:4px;">
                            Finding Product-Market-Fit (<$10K/mth)
                          </a>
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;margin:4% 0 0 0;padding:4% 0;line-height:1.5;font-weight:700;background-color:#fff;color:#15c;border:2px solid #15c;border-radius:4px;">
                            Startup Scaling (>$10K/mth)
                          </a>
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;margin:4% 0 0 0;padding:4% 0;line-height:1.5;font-weight:700;background-color:#fff;color:#15c;border:2px solid #15c;border-radius:4px;">
                            Business Scaling (>$100K/mth)
                          </a>
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;margin:4% 0 0 0;padding:4% 0;line-height:1.5;font-weight:700;background-color:#fff;color:#15c;border:2px solid #15c;border-radius:4px;">
                            Enterprise Scaling (>$1M/mth)
                          </a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
	      
	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        ⭐ Daily Sponsor
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:center;">
                        <p style="margin:3% 0 0 0;"><span style="color:#29303e;font-weight:700;font-size:1.2rem;font-family:sans-serif;line-height:1.5;">What Would You Do With An Extra 10, 100, or 1,000 New Leads Per Day!?!</span></p>
			<p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <img alt="" src="https://5dayleadchallenge.com/hosted/images/bf/1dcba62d6444f286b2d42c45c8103a/5DLC_Affiliate_1080x1080C.png" style="border-radius:5px;min-width:100px;min-height:100px;max-width:500px;max-height:500px;object-fit:cover;width:100%" />
                        </p>
			<p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.5;font-family:sans-serif;display:block;font-size:1rem;">
			  Join The "5 Day Lead Challenge" (FOR FREE) And Learn How To "Turn-On" An Endless Stream Of Hot Leads For Your Business!
			</p>
                        <p style="margin:4% 0 0 0;color:#2bb14c;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <a href="https://www.5dayleadchallenge.com/?cf_affiliate_id=831693&affiliate_id=831693" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1.5;font-weight:700;background-color:#2bb14c;color:#fff;border-radius:4px;">👉 JOIN THE "5 DAY LEAD CHALLENGE" FOR FREE!</a>
                        </p>
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <a href="https://twitter.com/intent/tweet?text=Join%20The%20%225%20Day%20Lead%20Challenge%22%20%28FOR%20FREE%29%20And%20Learn%20How%20To%20%22Turn-On%22%20An%20Endless%20Stream%20Of%20Hot%20Leads%20For%20Your%20Business%21&url=https%3A%2F%2Fwww.5dayleadchallenge.com%2F%3Fcf_affiliate_id%3D831693%26affiliate_id%3D831693&hashtags=CLICKFUNNELS,TRAFFIC,LEADS,10X&via=10XDaily" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🔥 Daily News
              </h1>
		
{{LOOP "news" "item"}}
<div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
<table style="padding:0px 0px;width:100%">
<tbody>
<tr>
<td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:center;">
<a href="{{LINK "item" "canonicalUrl"}}" style="text-decoration:none" target="_blank"><img alt="" src="{{TOPIC "item" "visualUrl"}}" style="border-radius:5px;min-width:100px;min-height:100px;max-width:500px;max-height:500px;object-fit:cover;width:100%"></a>
<p style="margin:3% 0 0 0;"><a href="{{LINK "item" "canonicalUrl"}}" style="text-decoration:none" target="_blank"><span style="color:#29303e;font-weight:700;font-size:1.2rem;font-family:sans-serif;line-height:1.3;">{{TOPIC "item" "title"}}</span></a></p>
<p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
<b>{{TOPIC "item" "topic"}}</b> • 
{{LOOP "item" "item_attribute_name" "item_attribute_value"}}
{{IF "((item_attribute_name STRING_EQ 'originTitle') LOGIC_AND (item_attribute_value STRING_NEQ ''))"}}
<a href="{{LINK "item" "originHtmlUrl"}}" target="_blank" style="color:#677489;text-decoration:none;">{{TOPIC "item" "originTitle"}}</a> • 
{{ENDIF}}
{{ENDLOOP}}
{{TOPIC "item" "engagementShort"}}&nbsp;•&nbsp;{{TOPIC "item" "publishedShort"}}
</p>
<p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
<a href="{{LINK "item" "shareUrl"}}" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
</p>
</td>
</tr>
</tbody>
</table>
</div>
{{ENDLOOP}}

	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        ❤️ Daily Meme
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:center;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <img alt="" src="https://media.tenor.com/2roX3uxz_68AAAAC/cat-space.gif" style="border-radius:5px;min-width:100px;min-height:100px;max-width:500px;max-height:500px;object-fit:cover;width:100%" />
                        </p>
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <a href="https://twitter.com/intent/tweet?text=Nyan%20Cat&url=https%3A%2F%2Ftenor.com%2Fview%2Fcat-space-nyan-cat-gif-22656380&hashtags=MEME&via=10XDaily" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🤓 Meta
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <b>{{RANDOM \`Hi\` \`Hello\` \`Hey\`}}:</b> [[firstname]]
                          <br><b>Date:</b> {{DATE \`YEAR-MONTH-DAY\`}}
                          <br><b>Time:</b> {{DATE \`HOUR:MINUTE:SECOND\`}}
                          <br><b>Campaign ID:</b> {{CONTACT \`campaign_id\`}}
                          <br><b>Message ID:</b> {{CONTACT \`message_id\`}}
                          <br><b>Subscriber ID:</b> {{CONTACT \`subscriber_id\`}}
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

            </td>
          </tr>
        </tbody>
      </table>
    </td></tr></tbody></table>
  </td></tr></tbody></table>
</td></tr></tbody></table>
`,
       "plain": `
`// TODO - dynamic plaintext version of the HTML email? (strip HTML)
      },
      "flags": [
        "openrate",
        "clicktrack"
        // "google_analytics" // requires higher paid plan. Adds UTM tracking on links in email, to be tracked on our Website
      ],
      "name": today.toISOString() + ' 10X NEWS DAILY', // TODO make timezone aware (e.g. Australia/Sydney). Note that .toISOString() always returns a timestamp in UTC
      "type": "broadcast", // draft or broadcast
      "editor": "custom",
      "subject": '10X NEWS ' + emoji + ' {{DATE "DAY_ORDINATED MONTH_NAME YEAR"}}',
      "fromField": {
        "fromFieldId": "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "replyTo": {
        "fromFieldId": "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "campaign": {
        "campaignId": "rJYER" // "LCJtj" // "Q1Oz0" // "10X Daily" subscriber list // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns
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
        "selectedCampaigns": ["rJYER"], // ["LCJtj"], // ["Q1Oz0"], // "10X Daily" subscriber list
        "selectedSegments": [],
        "selectedSuppressions": [],
        "excludedCampaigns": [],
        "excludedSegments": [],
        "selectedContacts": ["VWqT16E"], // ["V5p8EtA"], // ["VohAb0F"], // Contact ID for email subscriber "test+5@10x.day" // {campaignId} = Q1Oz0 // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns/Q1Oz0/contacts
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


/**
* Deals sent via GetResponse API. 
* Triggered via /dealsemail URL, or via Cloudflare Worker CRON
**/
async function sendDealsemail() {
  console.log('sendDealsemail start');
  return new Promise(async function (resolve) {
    let today = new Date(); // Cloudflare workers freeze time, see https://developers.cloudflare.com/workers/learning/security-model/
    let emojis = ["😀","😃","😄","😁","😆","😅","😂","🤣","😊","😇","🙂","🙃","😉","😌","😍","🥰","😘","😗","😙","😚","😋","😛","😝","😜","🤪","🤨","🧐","🤓","😎","🤩","🥳","😏","😒","😞","😔","😟","😕","🙁","☹️","😣","😖","😫","😩","🥺","😢","😭","😤","😠","😡","🤬","🤯","😳","🥵","🥶","😱","😨","😰","😥","😓","🤗","🤔","🤭","🤫","🤥","😶","😐","😑","😬","🙄","😯","😦","😧","😮","😲","🥱","😴","🤤","😪","😵","🤐","🥴","🤢","🤮","🤧","😷","🤒","🤕","🤑","🤠","😈","👿","👹","👺","🤡","💩","👻","👽","👾","🤖","🎃"];
    let emoji = emojis[Math.floor(Math.random()*emojis.length)];
    let endpoint = `${GR_API}${GR_API_NEWSLETTERS}`;
    let email_json = {
      "content": {
        "html": `
<table cellpadding="0" cellspacing="0" role="presentation" style="background-color:#f5f7fb;padding:4%;" width="100%"><tbody><tr><td align="center">
  <table cellpadding="0" cellspacing="0" role="presentation" style="max-width:500px" width="100%"><tbody><tr><td>
    <table align="center" cellpadding="0" cellspacing="0" role="presentation"><tbody><tr style="background-color:#f5f7fb"><td style="padding:0">
      <table align="center" cellpadding="0" cellspacing="0" role="presentation">
        <tbody>
          <tr style="background-color:#f5f7fb">
            <td>
	      
	      <h1 style="margin:0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🎁 Daily Deal
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:center;">
                        <p style="margin:0;"><span style="color:#29303e;font-weight:700;font-size:1.2rem;font-family:sans-serif;line-height:1.5;">Attention: Entrepreneurs, Small Business Owners, Online Marketers and Marketing Agencies...</span></p>
			<p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <img alt="" src="https://funnelhackingsecrets.com/hosted/images/e4/7a6d01fa7f4c35941a3e0e68ad6c7f/FHS-Affiliate-graphics-Ads-3a.jpg" style="border-radius:5px;min-width:100px;min-height:100px;max-width:500px;max-height:500px;object-fit:cover;width:100%" />
                        </p>
			<p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.5;font-family:sans-serif;display:block;font-size:1rem;">
			  Find Out Which Funnels Will Work The Best <u>For YOUR Specific Business!</u> (...plus a <b>MASSIVE 91% OFF</b> deal inside!)
			</p>
                        <p style="margin:4% 0 0 0;color:#2bb14c;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <a href="https://www.funnelhackingsecrets.com?cf_affiliate_id=831693&affiliate_id=831693" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1.5;font-weight:700;background-color:#2bb14c;color:#fff;border-radius:4px;">👉 REGISTER FOR THE FREE WEBCLASS NOW!</a>
                        </p>
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <a href="https://twitter.com/intent/tweet?text=%22The%20Weird%20%28Almost%20Backwards%29%20Funnel%20Secret%20That%20Is%20Currently%20Being%20Used%20By%20An%20Underground%20Group%20Of%20Entrepreneurs%20To%20Sell%20Almost%20Anything%20You%20Can%20Dream%20Of%21%22&url=https%3A%2F%2Fwww.funnelhackingsecrets.com%3Fcf_affiliate_id%3D831693%26affiliate_id%3D831693&hashtags=CLICKFUNNELS,10X,DEALS&via=10XDaily" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🤓 Meta
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <b>{{RANDOM \`Hi\` \`Hello\` \`Hey\`}}:</b> [[firstname]]
                          <br><b>Date:</b> {{DATE \`YEAR-MONTH-DAY\`}}
                          <br><b>Time:</b> {{DATE \`HOUR:MINUTE:SECOND\`}}
                          <br><b>Campaign ID:</b> {{CONTACT \`campaign_id\`}}
                          <br><b>Message ID:</b> {{CONTACT \`message_id\`}}
                          <br><b>Subscriber ID:</b> {{CONTACT \`subscriber_id\`}}
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

            </td>
          </tr>
        </tbody>
      </table>
    </td></tr></tbody></table>
  </td></tr></tbody></table>
</td></tr></tbody></table>
`,
       "plain": `
`// TODO - dynamic plaintext version of the HTML email? (strip HTML)
      },
      "flags": [
        "openrate",
        "clicktrack"
        // "google_analytics" // requires higher paid plan. Adds UTM tracking on links in email, to be tracked on our Website
      ],
      "name": today.toISOString() + ' 10X DEALS DAILY', // TODO make timezone aware (e.g. Australia/Sydney). Note that .toISOString() always returns a timestamp in UTC
      "type": "broadcast", // draft or broadcast
      "editor": "custom",
      "subject": '10X DEALS ' + emoji + ' {{DATE "DAY_ORDINATED MONTH_NAME YEAR"}}',
      "fromField": {
        "fromFieldId": "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "replyTo": {
        "fromFieldId": "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "campaign": {
        "campaignId": "rJYER" // "LCJtj" // "Q1Oz0" // "10X Daily" subscriber list // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns
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
        "selectedCampaigns": ["rJYER"], // ["LCJtj"], // ["Q1Oz0"], // "10X Daily" subscriber list
        "selectedSegments": [],
        "selectedSuppressions": [],
        "excludedCampaigns": [],
        "excludedSegments": [],
        "selectedContacts": ["VWqT16E"], // ["V5p8EtA"], // ["VohAb0F"], // Contact ID for email subscriber "test+5@10x.day" // {campaignId} = Q1Oz0 // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns/Q1Oz0/contacts
        "timeTravel": "false", // requires higher paid plan. Instead we will use a Segment, and user defined Custom Field "UTC Offset Timezone".
        "perfectTiming": "false"
//	,
//        "externalLexpad": {
//           "dataSourceUrl": X_API + X_API_LEXPAD,
//           "dataSourceToken": X_API_KEY
//        }
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


/**
* Stats sent via GetResponse API. 
* Triggered via /statsemail URL, or via Cloudflare Worker CRON
**/
async function sendStatsemail() {
  console.log('sendStatsemail start');
  return new Promise(async function (resolve) {
    let today = new Date(); // Cloudflare workers freeze time, see https://developers.cloudflare.com/workers/learning/security-model/
    let emojis = ["😀","😃","😄","😁","😆","😅","😂","🤣","😊","😇","🙂","🙃","😉","😌","😍","🥰","😘","😗","😙","😚","😋","😛","😝","😜","🤪","🤨","🧐","🤓","😎","🤩","🥳","😏","😒","😞","😔","😟","😕","🙁","☹️","😣","😖","😫","😩","🥺","😢","😭","😤","😠","😡","🤬","🤯","😳","🥵","🥶","😱","😨","😰","😥","😓","🤗","🤔","🤭","🤫","🤥","😶","😐","😑","😬","🙄","😯","😦","😧","😮","😲","🥱","😴","🤤","😪","😵","🤐","🥴","🤢","🤮","🤧","😷","🤒","🤕","🤑","🤠","😈","👿","👹","👺","🤡","💩","👻","👽","👾","🤖","🎃"];
    let emoji = emojis[Math.floor(Math.random()*emojis.length)];
    let endpoint = `${GR_API}${GR_API_NEWSLETTERS}`;
    let email_json = {
      "content": {
        "html": `
<table cellpadding="0" cellspacing="0" role="presentation" style="background-color:#f5f7fb;padding:4%;" width="100%"><tbody><tr><td align="center">
  <table cellpadding="0" cellspacing="0" role="presentation" style="max-width:500px" width="100%"><tbody><tr><td>
    <table align="center" cellpadding="0" cellspacing="0" role="presentation"><tbody><tr style="background-color:#f5f7fb"><td style="padding:0">
      <table align="center" cellpadding="0" cellspacing="0" role="presentation">
        <tbody>
          <tr style="background-color:#f5f7fb">
            <td>

	      <h1 style="margin:0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        💕 Referrals
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          Referral content here
			</p>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(170,0,255,1) 0%, rgba(0,138,255,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;width:33%;">
                                <b>10X Level</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Active Referrals</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Next Level</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                3
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                6
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                67%
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(255,0,0,1) 0%, rgba(255,230,0,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;width:33%;">
                                &nbsp;
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Referrals<br>(All Time)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Top 10 Avg.<br>(All Time)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>DIRECT</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;1</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;2</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;3</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;4</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;5</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;6</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;7</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;8</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;9</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL&nbsp;10</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.3);">
                              <td style="padding:2%;text-align:left;">
                                <b>TOTAL</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                <b>0</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                <b>10</b>
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
	      
	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        💵 Commissions
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          Commissions content here
			</p>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(170,0,255,1) 0%, rgba(0,138,255,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;width:33%;">
                                <b>10X Status</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Commissions<br>(All Time)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Top 10 Avg. Commissions<br>(All Time)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                Active
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $123,456.00
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(255,0,0,1) 0%, rgba(255,230,0,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;width:33%;">
                                &nbsp;
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Commissions<br>(This Week)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Top 10 Avg.<br>(This Week)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>DIRECT</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 1</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 2</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 3</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 4</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 5</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 6</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 7</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 8</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 9</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 10</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.3);">
                              <td style="padding:2%;text-align:left;">
                                <b>TOTAL</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                <b>$0.00</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                <b>$10.00</b>
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
	      
	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🌱 Organic Traffic
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          Organic traffic content here
			</p>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(170,0,255,1) 0%, rgba(0,138,255,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;width:33%;">
                                &nbsp;
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Organic Traffic<br>(This Week)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Top 10 Avg.<br>(This Week)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Shares</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                7
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Views</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                10
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Referrals</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Conversion</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0%
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                10%
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(255,0,0,1) 0%, rgba(255,230,0,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;width:33%;">
                                &nbsp;
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Organic Traffic<br>(All Time)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Top 10 Avg.<br>(All Time)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Shares</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                50
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                5000
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Referrals</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1000
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Commissions</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1000
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Life-Time-Value</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
	      
	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🚀 Paid Traffic
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          Traffic content here
			</p>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(170,0,255,1) 0%, rgba(0,138,255,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;width:33%;">
                                &nbsp;
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Paid Traffic<br>(This Week)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Top 10 Avg.<br>(This Week)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Spend</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $2,000.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Views</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                10
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Referrals</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                3
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Conversion</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0%
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                30%
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(255,0,0,1) 0%, rgba(255,230,0,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;width:33%;">
                                &nbsp;
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Paid Traffic<br>(All Time)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Top 10 Avg.<br>(All Time)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Cost</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $5000.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Revenue Re-invested</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $6000.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Referrals</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1000
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Cost-Per-Acquisition</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                -$1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Commissions</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $10,000
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Life-Time-Value</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $10
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
	      
	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🏆 Points
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          Points content here
			</p>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(170,0,255,1) 0%, rgba(0,138,255,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;width:33%;">
                                <b>Points Multiplier</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Points<br>(This Week)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Points<br>(All Time)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                7X
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                35pts<br>(7 x 5pts)
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                2,000pts
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(255,0,0,1) 0%, rgba(255,230,0,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;width:33%;">
                                &nbsp;
                              </td>
                              <td style="padding:2%;">
                                <b>1</b>
                              </td>
                              <td style="padding:2%;">
                                <b>2</b>
                              </td>
                              <td style="padding:2%;">
                                <b>3</b>
                              </td>
                              <td style="padding:2%;">
                                <b>4</b>
                              </td>
                              <td style="padding:2%;">
                                <b>5</b>
                              </td>
                              <td style="padding:2%;">
                                <b>6</b>
                              </td>
                              <td style="padding:2%;">
                                <b>7</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Open Daily News</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                10
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Open Daily Deals</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                10
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Share Daily</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                10
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Action Daily</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                10
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Sponsor Daily</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                1
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                10
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                0
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>Bonus Points</b>
                              </td>
                              <td colspan="7" style="padding:2px;text-align:left;background:rgba(255,255,255,0.5);">
	                        <p style="margin:3% 0 0 0;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                                  <b>70pts</b> (7 x 10pts) Weekly Streak!
			        </p>
	                        <p style="margin:3% 0 0 0;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                                  <b>7pts</b> (7 x 1pts) Special One Time Offer
			        </p>
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
	      
	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🎉 Rewards
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          Rewards content here
			</p>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(170,0,255,1) 0%, rgba(0,138,255,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;width:33%;">
                                <b>Rewards<br>(This Week)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Rewards<br>(This Month)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Rewards<br>(All Time)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1,000<br>($10 x 100 users)
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $4,000<br>($1,000 x 4 users)
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $123,456 (across 1,234 users)
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(255,0,0,1) 0%, rgba(255,230,0,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;width:33%;">
                                &nbsp;
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Your Rewards</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Top 10 Avg.</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>This Week</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>This Month</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $10.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>All Time</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $0.00
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $100.00
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🦄 10X DAO
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          10X DAO content here
			</p>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(170,0,255,1) 0%, rgba(0,138,255,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;width:33%;">
                                <b>Revenue<br>(This Week)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Costs<br>(This Week)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Profit<br>(This Week)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1,000
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $200
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $800
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(255,0,0,1) 0%, rgba(255,230,0,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;width:33%;">
                                <b>Revenue<br>(All Time)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Costs<br>(All Time)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Profit<br>(All Time)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $10,000
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $2,000
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $8,000
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          From the Commissions & Sponsor Fees that 10X Company keeps, we subtract operating costs (e.g. web hosting, email provider, etc) and then split and distribute profits WEEKLY as follows:
			  <br><b>50% Company:</b>
			  <br>&nbsp;&nbsp;&nbsp; 10% Company Cash Savings
			  <br>&nbsp;&nbsp;&nbsp; 10% Cash (or Bitcoin) to Current Team
			  <br>&nbsp;&nbsp;&nbsp; 10% Traffic to Current Team
			  <br>&nbsp;&nbsp;&nbsp; 10% Passive Income to Lifetime Team
			  <br>&nbsp;&nbsp;&nbsp; 10% Crypto Investment to Lifetime Team
			  <br><b>50% Community:</b>
			  <br>&nbsp;&nbsp;&nbsp; 10% Crypto Rekt
			  <br>&nbsp;&nbsp;&nbsp; 10% Bootstrapper Fund
			  <br>&nbsp;&nbsp;&nbsp; 10% Bonus Bounty
			  <br>&nbsp;&nbsp;&nbsp; 10% Weekly Rewards (Weekly 10X Points)
			  <br>&nbsp;&nbsp;&nbsp; 10% Monthly Rewards (Lifetime 10X Points) 			  
			</p>
			
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        ⚡ Zeus
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          Zeus content here
			</p>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(170,0,255,1) 0%, rgba(0,138,255,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;width:33%;">
                                <b>Organic Referrals<br>(All Time)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Paid Referrals<br>(All Time)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Commissions<br>(All Time)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                100
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                200
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $800,000
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
                        <table style="margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(255,0,0,1) 0%, rgba(255,230,0,1) 100%);color:rgba(0,0,0,0.5);">
                          <tbody>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;width:33%;">
                                &nbsp;
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Referrals<br>(This Week)</b>
                              </td>
                              <td style="padding:2%;width:33%;">
                                <b>Commissions<br>(This Week)</b>
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>DIRECT</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                50
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $100.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 1</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 2</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 3</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 4</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 5</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 6</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 7</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 8</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 9</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.5);">
                              <td style="padding:2%;text-align:left;">
                                <b>LEVEL 10</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                123
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                $1.00
                              </td>
                            </tr>
                            <tr style="background:rgba(255,255,255,0.3);">
                              <td style="padding:2%;text-align:left;">
                                <b>TOTAL</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                <b>456</b>
                              </td>
                              <td style="padding:2%;background:rgba(255,255,255,0.5);">
                                <b>$120.00</b>
                              </td>
                            </tr>
                          </tbody>
                        </table>
			
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          Zeus money spent this week on...
			</p>
			
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>
	      
	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        ✊ Team
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          Team content here... hours spent, proof of work, current team, lifetime team...
			</p>
			
                        <p style="margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;">
                          <a href="https://10x.day" target="_blank" style="display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;">SHARE</a>
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

	      <h1 style="margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;">
	        🤓 Meta
              </h1>
              <div style="margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd">
                <table style="padding:0px 0px;width:100%">
                  <tbody>
                    <tr>
                      <td style="padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;">
	                <p style="margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;">
                          <b>{{RANDOM \`Hi\` \`Hello\` \`Hey\`}}:</b> [[firstname]]
                          <br><b>Date:</b> {{DATE \`YEAR-MONTH-DAY\`}}
                          <br><b>Time:</b> {{DATE \`HOUR:MINUTE:SECOND\`}}
                          <br><b>Campaign ID:</b> {{CONTACT \`campaign_id\`}}
                          <br><b>Message ID:</b> {{CONTACT \`message_id\`}}
                          <br><b>Subscriber ID:</b> {{CONTACT \`subscriber_id\`}}
                        </p>
                      </td>
                    </tr>
                  </tbody>
                </table>
              </div>

            </td>
          </tr>
        </tbody>
      </table>
    </td></tr></tbody></table>
  </td></tr></tbody></table>
</td></tr></tbody></table>
`,
       "plain": `
`// TODO - dynamic plaintext version of the HTML email? (strip HTML)
      },
      "flags": [
        "openrate",
        "clicktrack"
        // "google_analytics" // requires higher paid plan. Adds UTM tracking on links in email, to be tracked on our Website
      ],
      "name": today.toISOString() + ' 10X STATS DAILY', // TODO make timezone aware (e.g. Australia/Sydney). Note that .toISOString() always returns a timestamp in UTC
      "type": "broadcast", // draft or broadcast
      "editor": "custom",
      "subject": '10X STATS ' + emoji + ' {{DATE "DAY_ORDINATED MONTH_NAME YEAR"}}',
      "fromField": {
        "fromFieldId": "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "replyTo": {
        "fromFieldId": "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "campaign": {
        "campaignId": "rJYER" // "LCJtj" // "Q1Oz0" // "10X Daily" subscriber list // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns
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
        "selectedCampaigns": ["rJYER"], // ["LCJtj"], // ["Q1Oz0"], // "10X Daily" subscriber list
        "selectedSegments": [],
        "selectedSuppressions": [],
        "excludedCampaigns": [],
        "excludedSegments": [],
        "selectedContacts": ["VWqT16E"], // ["V5p8EtA"], // ["VohAb0F"], // Contact ID for email subscriber "test+5@10x.day" // {campaignId} = Q1Oz0 // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns/Q1Oz0/contacts
        "timeTravel": "false", // requires higher paid plan. Instead we will use a Segment, and user defined Custom Field "UTC Offset Timezone".
        "perfectTiming": "false"
//	,
//        "externalLexpad": {
//           "dataSourceUrl": X_API + X_API_LEXPAD,
//           "dataSourceToken": X_API_KEY
//        }
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
  const cron_entries = await cacheEntries();
  console.log(cron_entries);
  const cron_news = await cacheNews();
  console.log(cron_news);
  const cron_newsemail = await sendNewsemail();
  console.log(cron_newsemail);
  const cron_dealsemail = await sendDealsemail();
  console.log(cron_dealsemail);
  const cron_statsemail = await sendStatsemail();
  console.log(cron_statsemail);
  console.log('cron logs end'); 
}
