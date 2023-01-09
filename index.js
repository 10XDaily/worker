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
EXPERIMENT - EveryNFT
*/
/*
Goals: 
- 1px vertical slice of every NFT in an NFT collection
- If 1000px x 1000px image, and > 1000 NFTs in collection, then randomly pick 1000 NFTs from the collection (to keep 1000 x 1000 image dimension)
- 5% Royalties split with original creator (80% original, 20% me)

POC assets:
- BAYC IPFS Image hosting - https://ipfs.io/ipfs/QmeSjSinHpPnmXmspMjwiXyN6zS4E9zccariGR3jxcaWtq/
- BAYC Dimensions = 631px x 631px
- BAYC #0 - https://ipfs.io/ipfs/QmRRPWG96cmgTn2qSzjwr2qvfNEuhunv6FNeMFGa9bx6mQ
- BAYC #1 - https://ipfs.io/ipfs/QmPbxeGcXhYQQNgsC6a36dDyYUcHgMLnGKnF8pVFmGsvqi
- BAYC #2 - https://ipfs.io/ipfs/QmcJYkCKK7QPmYWjp4FD2e3Lv5WCGFuHNUByvGKBaytif4
- BAYC #3 - https://ipfs.io/ipfs/QmYxT4LnK8sqLupjbS6eRvu1si7Ly2wFQAqFebxhWntcf6

POC References:
- Trim: https://developers.cloudflare.com/images/image-resizing/resize-with-workers/#trim
- An example worker: https://developers.cloudflare.com/images/image-resizing/resize-with-workers/#an-example-worker
- Draw overlays & watermarks: https://developers.cloudflare.com/images/image-resizing/draw-overlays/
- Draw combined into one image: https://developers.cloudflare.com/images/image-resizing/draw-overlays/#combined

POC Goal:
- Show left 50% of BAYC #0 (trim)
- Show right 50% of BAYC #1 (trim)
- Draw both onto one image i.e. 50/50 split (draw combined)
- Do the same for BAYC #2 & BAYC #3 on a separate image
- Draw all 4 onto one image i.e. 25/25/25/25 split (draw combined)
- Draw as a 1px vertical slice for each of the 4 images i.e. total of 4px width
- Choose BAYC's at random from IPFS (0-9999)
- Remove possibility of duplicates in the random selection
- Random choice seeded by a specific date (NOW GMT as the default)
- Pass in a specific date as a URL parameter 
*/
router.get("/nft", async request => {
  console.log("nft logs");
  
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
  
    //const nft_image = await generateNFT();
    //console.log(nft_image);
    
console.log("Test AFTER generateNFT");

    let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
    let html_content = '<h1>Success!!!</h1>';
    // html_content += `<p>... add more HTML to confirm the email sent successfully</p>`; // TODO

    let html = `
  <!DOCTYPE html>
  <head>
    <title>NFT: Generated</title>
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
<html><head>
<style>
#x .hidden {display:none;}
#x .a{margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;}
#x .b{margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd;}
#x .c{padding:0px 0px;width:100%;}
#x .d{padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:center;}
#x .e{margin:3% 0 0 0;color:#29303e;font-weight:900;font-size:1.5rem;font-family:sans-serif;line-height:1.5;}
#x .f{color:#677489;}
#x .g{margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;}
#x .h{display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;}
#x .i{color:#29303e;font-weight:700;font-size:1.2rem;font-family:sans-serif;line-height:1.3;}
#x .j{display:block;text-decoration:none;width:100%;margin:4% 0 0 0;padding:4% 0;line-height:1.5;font-weight:700;background-color:#fff;color:#15c;border:2px solid #15c;border-radius:4px;}
#x .k{color:#29303e;font-weight:700;font-size:1.2rem;font-family:sans-serif;line-height:1.5;}
#x .l{margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;}
#x .m{margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.5;font-family:sans-serif;display:block;font-size:1rem;}
#x .n{margin:4% 0 0 0;color:#2bb14c;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;}
#x .o{border-radius:5px;min-width:100px;min-height:100px;max-width:500px;max-height:500px;object-fit:cover;width:100%}
#x .p{display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1.5;font-weight:700;background-color:#2bb14c;color:#fff;border-radius:4px;}
#x .q{margin:3% 0 0 0;}
#x .r{margin:3% 0 0 0;}
#x .s{color:#677489;text-decoration:none;}
#x .t{text-decoration:none}
#x .u{padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;}
#x .v{margin:0;}
</style>
</head>
<body>
<table id="x" cellpadding="0" cellspacing="0" role="presentation" style="background-color:#f5f7fb;padding:4%;" width="100%"><tbody><tr><td align="center">
	<table cellpadding="0" cellspacing="0" role="presentation" style="max-width:500px" width="100%"><tbody><tr><td>
		<table align="center" cellpadding="0" cellspacing="0" role="presentation"><tbody><tr style="background-color:#f5f7fb"><td style="padding:0">
			<table align="center" cellpadding="0" cellspacing="0" role="presentation"><tbody><tr style="background-color:#f5f7fb"><td>

<div class="hidden">{{TOPIC "featuredMemeLabels"}}</div>

<h1 class="a" style="margin:0;">🚧 Work In Progress</h1>
<div class="b" style="background-color:lightyellow;"><table class="c"><tbody><tr><td class="d">
	<p class="v"><span class="k">10X News is under construction</span></p>
	<p class="m">We're working hard to bring you Daily Quote, Action, Sponsor &amp; Meme... but for now, these sections are just showing examples to give you an idea of what we're building for you.</p>
	<p class="m"><b>UPDATE: Daily News is available! 🥳</b></p>
</td></tr></tbody></table></div>

<h1 class="a">🤘 Daily Quote</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e">“Knowledge is Power ⚡ Money is Freedom” <span class="f">—&nbsp;10X&nbsp;Daily</span></p>
	<p class="g"><a class="h" href="https://twitter.com/intent/tweet?text=%E2%80%9CKnowledge%20is%20Power%20%E2%9A%A1%20Money%20is%20Freedom%E2%80%9D%20%E2%80%94%2010X%20Daily&url=https%3A%2F%2F10x.day&hashtags=10X&via=10XDaily" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>
				
<h1 class="a">⚡ Daily Action</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="v"><span class="i">Poll: Do you have a business?</span></p>
	<p class="g">
		<a class="j" href="https://10x.day" target="_blank">Nope, not interested</a>
		<a class="j" href="https://10x.day" target="_blank">Thinking up ideas</a>
		<a class="j" href="https://10x.day" target="_blank">In development (Pre-launch)</a>
		<a class="j" href="https://10x.day" target="_blank">Launched (Pre-revenue)</a>
		<a class="j" href="https://10x.day" target="_blank">Finding Product-Market-Fit (&lt;$10K/mth)</a>
		<a class="j" href="https://10x.day" target="_blank">Startup Scaling (&gt;$10K/mth)</a>
		<a class="j" href="https://10x.day" target="_blank">Business Scaling (&gt;$100K/mth)</a>
		<a class="j" href="https://10x.day" target="_blank">Enterprise Scaling (&gt;$1M/mth)</a>
	</p>
</td></tr></tbody></table></div>

<h1 class="a">⭐ Daily Sponsor</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="q"><span class="k">What Would You Do With An Extra 10, 100, or 1,000 New Leads Per Day!?!</span></p>
	<p class="l"><img alt="" class="o" src="https://5dayleadchallenge.com/hosted/images/bf/1dcba62d6444f286b2d42c45c8103a/5DLC_Affiliate_1080x1080C.png"></p>
	<p class="m">Join The "5 Day Lead Challenge" (FOR FREE) And Learn How To "Turn-On" An Endless Stream Of Hot Leads For Your Business!</p>
	<p class="n"><a class="p" href="https://www.5dayleadchallenge.com/?cf_affiliate_id=831693&affiliate_id=831693" target="_blank">👉 JOIN THE "5 DAY LEAD CHALLENGE" FOR FREE!</a></p>
	<p class="g"><a class="h" href="https://twitter.com/intent/tweet?text=Join%20The%20%225%20Day%20Lead%20Challenge%22%20%28FOR%20FREE%29%20And%20Learn%20How%20To%20%22Turn-On%22%20An%20Endless%20Stream%20Of%20Hot%20Leads%20For%20Your%20Business%21&url=https%3A%2F%2Fwww.5dayleadchallenge.com%2F%3Fcf_affiliate_id%3D831693%26affiliate_id%3D831693&hashtags=CLICKFUNNELS,TRAFFIC,LEADS,10X&via=10XDaily" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🔥 Daily News</h1>
{{LOOP "news" "item"}}
<div class="b"><table class="c"><tbody><tr><td class="d">
	<a href="{{LINK "item" "canonicalUrl"}}" class="t" target="_blank"><img alt="" src="{{TOPIC "item" "visualUrl"}}" class="o"></a>
	<p class="r"><a href="{{LINK "item" "canonicalUrl"}}" class="t" target="_blank"><span class="i">{{TOPIC "item" "title"}}</span></a></p>
<p class="l">
<b>{{TOPIC "item" "topic"}}</b> • 
<a href="{{LINK "item" "streamUrl"}}" target="_blank" class="s">{{TOPIC "item" "streamName"}}</a> • 
{{TOPIC "item" "engagementShort"}}&nbsp;•&nbsp;{{TOPIC "item" "publishedShort"}}
</p>
	<p class="g"><a href="{{LINK "item" "shareUrl"}}" target="_blank" class="h">SHARE</a></p>
</td></tr></tbody></table></div>
{{ENDLOOP}}

<h1 class="a">❤️ Daily Meme</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="l"><img alt="" class="o" src="https://media.tenor.com/2roX3uxz_68AAAAC/cat-space.gif"></p>
	<p class="g"><a class="h" href="https://twitter.com/intent/tweet?text=Nyan%20Cat&url=https%3A%2F%2Ftenor.com%2Fview%2Fcat-space-nyan-cat-gif-22656380&hashtags=MEME&via=10XDaily" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🤓 Meta</h1>
<div class="b"><table class="c"><tbody><tr><td class="u">
	<p class="l"><b>{{RANDOM \`Hi\` \`Hello\` \`Hey\`}}:</b> [[firstname]]<br>
	<b>Date:</b> {{DATE \`YEAR-MONTH-DAY\`}}<br>
	<b>Time:</b> {{DATE \`HOUR:MINUTE:SECOND\`}}<br>
	<b>Campaign ID:</b> {{CONTACT \`campaign_id\`}}<br>
	<b>Message ID:</b> {{CONTACT \`message_id\`}}<br>
	<b>Subscriber ID:</b> {{CONTACT \`subscriber_id\`}}</p>
</td></tr></tbody></table></div>

			</td></tr></tbody></table>
		</td></tr></tbody></table>
	</td></tr></tbody></table>
</td></tr></tbody></table>
</body></html>
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
        "fromFieldId": "KxrZX" // "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "replyTo": {
        "fromFieldId": "KxrZX" // "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "campaign": {
        "campaignId": "rRTkV" // "rJYER" // "LCJtj" // "Q1Oz0" // "10X Daily" subscriber list // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns
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
        "selectedCampaigns": ["rRTkV"], // ["rJYER"], // ["LCJtj"], // ["Q1Oz0"], // "10X Daily" subscriber list
        "selectedSegments": [],
        "selectedSuppressions": [],
        "excludedCampaigns": [],
        "excludedSegments": [],
        "selectedContacts": ["VKVmI6q"], // "VK7KbWJ", "VK7Ba8m"], // test, me, stuart // ["VWqT16E"], // ["V5p8EtA"], // ["VohAb0F"], // Contact ID for email subscriber "test+5@10x.day" // {campaignId} = Q1Oz0 // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns/Q1Oz0/contacts
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
<html><head>
<style>
#x .a{margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;}
#x .b{margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd;}
#x .c{padding:0px 0px;width:100%;}
#x .d{padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:center;}
#x .e{color:#29303e;font-weight:700;font-size:1.2rem;font-family:sans-serif;line-height:1.5;}
#x .f{margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;}
#x .g{border-radius:5px;min-width:100px;min-height:100px;max-width:500px;max-height:500px;object-fit:cover;width:100%;}
#x .h{margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.5;font-family:sans-serif;display:block;font-size:1rem;}
#x .i{margin:4% 0 0 0;color:#2bb14c;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;}
#x .j{display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1.5;font-weight:700;background-color:#2bb14c;color:#fff;border-radius:4px;}
#x .k{margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;}
#x .l{display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;}
#x .m{}
#x .n{padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;}
#x .o{margin:0;}
</style>
</head>
<body>
<table id="x" cellpadding="0" cellspacing="0" role="presentation" style="background-color:#f5f7fb;padding:4%;" width="100%"><tbody><tr><td align="center">
	<table cellpadding="0" cellspacing="0" role="presentation" style="max-width:500px" width="100%"><tbody><tr><td>
		<table align="center" cellpadding="0" cellspacing="0" role="presentation"><tbody><tr style="background-color:#f5f7fb"><td style="padding:0">
			<table align="center" cellpadding="0" cellspacing="0" role="presentation"><tbody><tr style="background-color:#f5f7fb"><td>

<h1 class="a" style="margin:0;">🚧 Work In Progress</h1>
<div class="b" style="background-color:lightyellow;"><table class="c"><tbody><tr><td class="d">
	<p class="o"><span class="e">10X Deals is under construction</span></p>
	<p class="h">We're in the process of finding you the BEST daily deals... while you wait, please check out the incredible offer below!</p>
</td></tr></tbody></table></div>

<h1 class="a">🎁 Daily Deal</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="o"><span class="e">Attention: Entrepreneurs, Small Business Owners, Online Marketers and Marketing Agencies...</span></p>
	<p class="f"><img alt="" class="g" src="https://funnelhackingsecrets.com/hosted/images/e4/7a6d01fa7f4c35941a3e0e68ad6c7f/FHS-Affiliate-graphics-Ads-3a.jpg"></p>
	<p class="h">Find Out Which Funnels Will Work The Best <u>For YOUR Specific Business!</u> (...plus a <b>MASSIVE 91% OFF</b> deal inside!)</p>
	<p class="i"><a class="j" href="https://www.funnelhackingsecrets.com?cf_affiliate_id=831693&affiliate_id=831693" target="_blank">👉 REGISTER FOR THE FREE WEBCLASS NOW!</a></p>
	<p class="k"><a class="l" href="https://twitter.com/intent/tweet?text=%22The%20Weird%20%28Almost%20Backwards%29%20Funnel%20Secret%20That%20Is%20Currently%20Being%20Used%20By%20An%20Underground%20Group%20Of%20Entrepreneurs%20To%20Sell%20Almost%20Anything%20You%20Can%20Dream%20Of%21%22&url=https%3A%2F%2Fwww.funnelhackingsecrets.com%3Fcf_affiliate_id%3D831693%26affiliate_id%3D831693&hashtags=CLICKFUNNELS,10X,DEALS&via=10XDaily" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🤓 Meta</h1>
<div class="b"><table class="c"><tbody><tr><td class="n">
	<p class="f"><b>{{RANDOM \`Hi\` \`Hello\` \`Hey\`}}:</b> [[firstname]]<br>
	<b>Date:</b> {{DATE \`YEAR-MONTH-DAY\`}}<br>
	<b>Time:</b> {{DATE \`HOUR:MINUTE:SECOND\`}}<br>
	<b>Campaign ID:</b> {{CONTACT \`campaign_id\`}}<br>
	<b>Message ID:</b> {{CONTACT \`message_id\`}}<br>
	<b>Subscriber ID:</b> {{CONTACT \`subscriber_id\`}}</p>
</td></tr></tbody></table></div>

			</td></tr></tbody></table>
		</td></tr></tbody></table>
	</td></tr></tbody></table>
</td></tr></tbody></table>
</body></html>
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
        "fromFieldId": "KxrZX" // "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "replyTo": {
        "fromFieldId": "KxrZX" // "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "campaign": {
        "campaignId": "rRTkV" // "rJYER" // "LCJtj" // "Q1Oz0" // "10X Daily" subscriber list // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns
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
        "selectedCampaigns": ["rRTkV"], // ["rJYER"], // ["LCJtj"], // ["Q1Oz0"], // "10X Daily" subscriber list
        "selectedSegments": [],
        "selectedSuppressions": [],
        "excludedCampaigns": [],
        "excludedSegments": [],
        "selectedContacts": ["VKVmI6q"], // "VK7KbWJ", "VK7Ba8m"], // test, me, stuart // ["VWqT16E"], // ["V5p8EtA"], // ["VohAb0F"], // Contact ID for email subscriber "test+5@10x.day" // {campaignId} = Q1Oz0 // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns/Q1Oz0/contacts
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
<html><head>
<style>
#x .a{margin:8% 0 0 0;color:#29303e;font-weight:700;font-size:1.5rem;font-family:sans-serif;line-height:1;}
#x .b{margin:6% 0 0 0;padding:4% 4%;background-color:#fff;border-radius:10px;border:1px solid #dddddd;}
#x .c{padding:0px 0px;width:100%;}
#x .d{padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:left;}
#x .e{margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;}
#x .f{margin:5% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(170,0,255,1) 0%, rgba(0,138,255,1) 100%);color:rgba(0,0,0,0.5);}
#x .g{background:rgba(255,255,255,0.5);}
#x .h{padding:2%;width:33%;}
#x .i{padding:2%;background:rgba(255,255,255,0.5);}
#x .j{margin:3% 0 0 0;padding:0px;width:100%;border-radius:4px;text-align:center;border-collapse:separate;border-spacing:1px;background:linear-gradient(0deg, rgba(255,0,0,1) 0%, rgba(255,230,0,1) 100%);color:rgba(0,0,0,0.5);}
#x .k{display:block;background-color:rgba(255,255,255,0.25);border-radius:4px;font-size:0.9rem;font-weight:normal;line-height:1;padding:5% 10%;margin-top:5%;}
#x .l{padding:2%;text-align:left;}
#x .m{background:rgba(255,255,255,0.3);}
#x .n{margin:4% 0 0 0;color:#677489;font-weight:700;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;}
#x .o{display:block;text-decoration:none;width:100%;padding:4% 0;line-height:1;font-weight:700;background-color:#15c;color:#fff;border-radius:4px;}
#x .p{margin:4% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;text-align:center;}
#x .q{color:#000;background-color:yellow;padding:1%;border-radius:4px;border:2px dashed rgba(0,0,0,0.25);text-decoration:none;}
#x .r{padding:2%;width:9%;}
#x .s{padding:0%;background:rgba(255,255,255,0.5);}
#x .t{padding:2%;text-align:left;background:rgba(255,255,255,0.5);}
#x .u{margin:0;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;}
#x .v{margin:2% 0 0 0;color:#677489;font-weight:400;line-height:1.3;font-family:sans-serif;display:block;font-size:1rem;}
#x .w{text-decoration:underline;color:#677489;}
#x .x{text-decoration:none;color:rgba(0,0,0,0.5);}
#x .y{color:rgba(0,0,0,0.5);}
#x .z{padding:2%;text-align:center;}
#x .aa {margin:0;}
#x .ab {color:#29303e;font-weight:700;font-size:1.2rem;font-family:sans-serif;line-height:1.5;}
#x .ac {margin:3% 0 0 0;color:#677489;font-weight:400;line-height:1.5;font-family:sans-serif;display:block;font-size:1rem;}
#x .ad {padding:0;color:#64748b;font-weight:500;line-height:1.3;font-family:Arial,-apple-system,'Segoe UI',sans-serif;display:block;font-size:1rem;text-align:center;}
</style>
</head>
<body>
<table id="x" cellpadding="0" cellspacing="0" role="presentation" style="background-color:#f5f7fb;padding:4%;" width="100%"><tbody><tr><td align="center">
	<table cellpadding="0" cellspacing="0" role="presentation" style="max-width:500px" width="100%"><tbody><tr><td>
		<table align="center" cellpadding="0" cellspacing="0" role="presentation"><tbody><tr style="background-color:#f5f7fb"><td style="padding:0">
			<table align="center" cellpadding="0" cellspacing="0" role="presentation"><tbody><tr style="background-color:#f5f7fb"><td>

<h1 class="a" style="margin:0;">🚧 Work In Progress</h1>
<div class="b" style="background-color:lightyellow;"><table class="c"><tbody><tr><td class="ad">
	<p class="aa"><span class="ab">10X Stats is under construction</span></p>
	<p class="ac">We're on a mission to build the world's first truly FREE, scalable &amp; sustainable "Passive Income Machine"... but for now, this email just contains hardcoded example data to give you a glimpse into the future!</p>
</td></tr></tbody></table></div>

<h1 class="a">💕 Referrals</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>More Referrals = More <i>Potential</i> Income</b></p>
	<p class="e">Grow your direct referrals by sharing 10X with family, friends & followers... then sit back and watch your network of referrals grow on autopilot to Level 10!</p>
	<p class="e">You only need <b>1</b> more Active Referrals to get to <b>LEVEL&nbsp;1!</b></p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h"><b>10X Level</b></td>
				<td class="h"><b>Active Referrals</b></td>
				<td class="h"><b>Next Level</b></td>
			</tr>
			<tr class="g">
				<td class="i">0</td>
				<td class="i">0</td>
				<td class="i">0%</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h">&nbsp;</td>
				<td class="h"><b>You<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Top 10 Avg.<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>DIRECT</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 1</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 2</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 3</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 4</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 5</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 6</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 7</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 8</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 9</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 10</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="m">
				<td class="l"><b>TOTAL</b></td>
				<td class="i"><b>0</b></td>
				<td class="i"><b>0</b></td>
			</tr>
		</tbody>
	</table>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">💵 Passive Income</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>More <i>Passive</i> Income = More Freedom</b></p>
	<p class="e">If your Direct Referrals purchase a 10X Deal you can earn 50% of the commission... plus, your Network Referrals can earn you up to 5% each from Level 1 to Level 10!</p>
	<p class="e">Your 10X Level is currently <b>0</b> so you can earn income up to <b>LEVEL&nbsp;0&nbsp;(DIRECT)</b>... and your 10X Status is <b>ACTIVE</b> so you are <b>ELIGIBLE</b> for earning income this week!</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h"><b>10X Status</b></td>
				<td class="h"><b>You<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Top 10 Avg.<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="i">Active</td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>You<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Top 10 Avg.<br><span class="k">This Week</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>DIRECT</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 1</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 2</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 3</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 4</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 5</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 6</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 7</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 8</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 9</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 10</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="m">
				<td class="l"><b>TOTAL</b></td>
				<td class="i"><b>$0.00</b></td>
				<td class="i"><b>$0.00</b></td>
			</tr>
		</tbody>
	</table>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🌱 Organic Traffic</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>Organic Traffic = <i>FREE</i> Referrals</b></p>
	<p class="e">Your daily 10X News email is filled with today's most popular content... if you maintain the habit of sharing content each day it will fuel your organic traffic and increase your direct referrals!</p>
	<p class="p">Share your referral link everywhere!</p>
	<p class="e"><b><a class="q" href="https://10X.day?ref=123" target="_blank">https://10X.day?ref=123</a></b></p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>You<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Top 10 Avg.<br><span class="k">This Week</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Shares</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>You<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Top 10 Avg.<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Shares</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LTV</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🚀 Paid Traffic</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>Paid Traffic = <i>Automated</i> Referrals</b></p>
	<p class="e">Paid traffic is the fastest and most scalable way to accelerate the growth of your direct referrals... 10X runs paid advertising campaigns on your behalf without you ever paying us a single cent from your own pocket!</p>
	<p class="e">How?! If you earn Passive Income, then 50% automatically gets invested into Paid Traffic... and if that traffic produces revenue within 100 days, then it gets reinvested into more paid traffic!</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>You<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Top 10 Avg.<br><span class="k">This Week</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Cost</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Revenue Reinvested</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>You<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Top 10 Avg.<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Cost</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Revenue Reinvested</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>CPA</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LTV</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🏆 Points</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>More Points = More <i>Potential</i> Rewards</b></p>
	<p class="e">Earn points by completing any of the 5 simple daily tasks... the more points you earn each week increases your chances of winning Rewards (i.e. Paid Traffic)!</p>
	<p class="e">You earn 1pt for completing a task and if you maintain an unbroken streak for 7 days you earn 10pts... also, if you continue a streak for all 5 tasks this week then you increase your Points Multiplier by +1 (all the way up to 10X)!</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h"><b>Points Multiplier</b></td>
				<td class="h"><b>You<br><span class="k">This Week</span></b></td>
				<td class="h"><b>You<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="i">1X</td>
				<td class="i">0pts<br><span class="k">1 x 0pts</span></td>
				<td class="i">0pts</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="r"><b>1</b></td>
				<td class="r"><b>2</b></td>
				<td class="r"><b>3</b></td>
				<td class="r"><b>4</b></td>
				<td class="r"><b>5</b></td>
				<td class="r"><b>6</b></td>
				<td class="r"><b>7</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Open News Email</b></td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Open Deals Email</b></td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Share Email Content</b></td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Complete Daily Action</b></td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Visit Daily Sponsor</b></td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
				<td class="s">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Bonus Points</b></td>
				<td class="t" colspan="7">
					<p class="u"><b>0pts</b> (1 x 0pts)</p>
				</td>
			</tr>
		</tbody>
	</table>
	<p class="v" style="margin:5% 0 0 0;"><b>Your Streak:</b></p>
	<p class="v">📧 0 Open News Email</p>
	<p class="v">🧧 0 Open Deals Email</p>
	<p class="v">👍 0 Share Email Content</p>
	<p class="v">✅ 0 Complete Daily Action</p>
	<p class="v">🌟 0 Visit Daily Sponsor</p>
	<p class="v">🖐🏽 0 Complete All 5 Tasks</p>
	<p class="v" style="margin:5% 0 0 0;"><b>Top 10 Avg. Streak:</b></p>
	<p class="v">📧 0 Open News Email</p>
	<p class="v">🧧 0 Open Deals Email</p>
	<p class="v">👍 0 Share Email Content</p>
	<p class="v">✅ 0 Complete Daily Action</p>
	<p class="v">🌟 0 Visit Daily Sponsor</p>
	<p class="v">🖐🏽 0 Complete All 5 Tasks</p>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🎉 Rewards</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>More Rewards = More <i>Paid</i> Traffic</b></p>
	<p class="e">Rewards of Paid Traffic can be earnt each week and month... helping boost the automated growth of your direct referrals.</p>
	<p class="e">Weekly Rewards are based on your points earnt "This Week" and are awarded to as many users as possible... while Monthly Rewards are based on your points earnt across "All Time" and are designed to be as BIG as possible!</p>
	<p class="e">#10X Social Rewards randomly gives $1 to $100 Paid Traffic to users engaging on social media with the hashtag #10X</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h"><b>Weekly Rewards</b></td>
				<td class="h"><b>Monthly Rewards</b></td>
				<td class="h"><b>All Time Rewards</b></td>
			</tr>
			<tr class="g">
				<td class="i">$0.00<br><span class="k">$0.00 x 0&nbsp;users</span></td>
				<td class="i">$0.00<br><span class="k">$0.00 x 0&nbsp;users</span></td>
				<td class="i">$0.00<br><span class="k">0&nbsp;users</span></td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>You</b></td>
				<td class="h"><b>Top 10 Avg.</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>This Week</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>This Month</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>All Time</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<p class="v" style="margin:5% 0 0 0;"><b>#10X Social Rewards:</b></p>
	<p class="v">🐦 $0.00 to <a class="w" href="https://10x.day" target="_blank">@User1</a> for LIKE on <a class="w" href="https://10x.day" target="_blank">Twitter</a></p>
	<p class="v">📘 $0.00 to <a class="w" href="https://10x.day" target="_blank">@User2</a> for LIKE on <a class="w" href="https://10x.day" target="_blank">Facebook</a></p>
	<p class="v">🤘 $0.00 to <a class="w" href="https://10x.day" target="_blank">@User3</a> for POST on <a class="w" href="https://10x.day" target="_blank">Coub</a></p>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">⚡ Zeus</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>Zeus = <i>Top</i> Level User</b></p>
	<p class="e">The 10X referral program has a system user named Zeus sitting in the highest position... Zeus is the Direct Referrer of 10X Team members and all non-referred signups.</p>
	<p class="e">Income earnt by Zeus is split 50% Traffic / 50% Profits... Profits go into a treasury that is transparently spent on community proposals (like #10X Social Rewards, influencer campaigns, licensing bonuses, contracting copywriters, etc).</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h"><b>Non-Referrals<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Paid Referrals<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Income<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="i">0</td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>Referrals<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Income<br><span class="k">This Week</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>DIRECT</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 1</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 2</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 3</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 4</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 5</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 6</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 7</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 8</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 9</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>LEVEL 10</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="m">
				<td class="l"><b>TOTAL</b></td>
				<td class="i"><b>0</b></td>
				<td class="i"><b>$0.00</b></td>
			</tr>
		</tbody>
	</table>
	<p class="v" style="margin:5% 0 0 0;"><b>Zeus's Treasury:</b></p>
	<p class="v">🔱 $0.00 Earnt</p>
	<p class="v">👑 $0.00 Spent</p>
	<p class="v">💛 $0.00 Saved</p>
	<p class="v" style="margin:3% 0 0 0;"><b>Funds recently spent on:</b></p>
	<p class="v">😊 $0.00 #10X Social Rewards</p>
	<p class="v">😎 $0.00 Example Campaign</p>
	<p class="v">🎀 $0.00 Example Bonus</p>
	<p class="v">🖊️ $0.00 Example Contractor</p>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🦄 10X DAO</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>10X <i>Decentralized</i> Autonomous Organization</b></p>
	<p class="e">10X operates transparently as a Global, Bootstrapped, Open Startup building the world's first truly FREE, scalable &amp; sustainable "Passive Income Machine".</p>
	<p class="e">Our long-term goal is to be owned and operated by our community of users through progressive decentralization... 1st&nbsp;Product/Market Fit, 2nd&nbsp;Community Participation and 3rd&nbsp;Sufficient Decentralization (community ownership).</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h"><b>Revenue<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Costs<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Profit<br><span class="k">This Week</span></b></td>
			</tr>
			<tr class="g">
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h"><b>Revenue<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Costs<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Profit<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<p class="v" style="margin:5% 0 0 0;">Profits are distributed WEEKLY as follows...</p>
	<p class="v" style="margin:3% 0 0 0;"><b>50% Team:</b></p>
	<p class="v">🏦 10% Savings</p>
	<p class="v">🪙 10% Cash or Bitcoin (Current Team)</p>
	<p class="v">🚀 10% Paid Traffic (Current Team)</p>
	<p class="v">🏖️ 10% Passive Income (Lifetime Team)</p>
	<p class="v">📈 10% Crypto Portfolio (Lifetime Team)</p>
	<p class="v" style="margin:3% 0 0 0;"><b>50% Community:</b></p>
	<p class="v">📉 10% Crypto Rekt</p>
	<p class="v">🥾 10% Bootstrap Fund</p>
	<p class="v">💖 10% Bonus Bounty</p>
	<p class="v">🎊 10% Weekly Rewards</p>
	<p class="v">🎉 10% Monthly Rewards</p>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">✊ Team</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>Built by Side-Hustlers <i>for</i> Side-Hustlers</b></p>
	<p class="e">10X is a "lifestyle business" that earns you money outside of your day job (in just a few hours per week)... stop trading time for money and escape the rat race by building lifelong assets!</p>
	<p class="e">As a team member you "bank a week" by contributing 10+&nbsp;hours (across 1 or more weeks) and then provide Proof-of-Contribution... the more weeks you bank the more you own and can earn from Current Team and Lifetime Team profits.</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>Contribution<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Hours<br><span class="k">This Week</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b><a class="x" href="https://twitter.com/chrisleejacob" target="_blank">Chris Jacob</a></b></td>
				<td class="i"><a class="y" href="https://twitter.com/chrisleejacob" target="_blank">2099-01-01</a></td>
				<td class="i">0</td>
			</tr>
			<tr class="m">
				<td class="l"><b>Total</b></td>
				<td class="i">1</td>
				<td class="i">0</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>Team</b></td>
				<td class="h"><b>Weeks Banked</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b><a class="x" href="https://twitter.com/chrisleejacob" target="_blank">Chris Jacob</a></b></td>
				<td class="i">Current</td>
				<td class="i">0</td>
			</tr>
			<tr class="m">
				<td class="l"><b>Total</b></td>
				<td class="i">1</td>
				<td class="i">0</td>
			</tr>
		</tbody>
	</table>
	<p class="v" style="margin:5% 0 0 0;"><b>Savings (All Time):</b></p>
	<p class="v">💰 $0.00 Earnt</p>
	<p class="v">💸 $0.00 Spent</p>
	<p class="v">🔒 $0.00 Saved</p>
	<p class="v" style="margin:3% 0 0 0;"><b>Cash or Bitcoin (This Week):</b></p>
	<p class="v">🪙 $0.00 Total</p>
	<p class="v">💃 1 Current Team Members</p>
	<p class="v">💗 $0.00 each Current Team Member</p>
	<p class="v" style="margin:3% 0 0 0;"><b>Paid Traffic (All Time):</b></p>
	<p class="v">🚀 $0.00 Spent</p>
	<p class="v">💕 0 Referrals</p>
	<p class="v">💵 $0.00 Income</p>
	<p class="v" style="margin:3% 0 0 0;"><b>Passive Income (This Week):</b></p>
	<p class="v">👻 1 Lifetime Team Members</p>
	<p class="v">🔅 $0.00 Lowest</p>
	<p class="v">🔆 $0.00 Highest</p>
	<p class="v" style="margin:3% 0 0 0;"><b>Crypto Portfolio:</b></p>
	<p class="v">🌑 $0.00 Bitcoin (50%)</p>
	<p class="v">🌒 $0.00 Ethereum (20%)</p>
	<p class="v">🌓 $0.00 Cardano (10%)</p>
	<p class="v">🌔 $0.00 Solana (10%)</p>
	<p class="v">🌕 $0.00 Moonshots (10%)</p>
	<p class="v">🧑‍🚀 $0.00 Total Portfolio Value (+0.00%)</p>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">👏 Community</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>Community is <i>Everything</i></b></p>
	<p class="e"><a class="w" href="https://10x.day" target="_blank">Crypto Rekt</a> is helping <b>0</b> crypto adopters who have experienced 80% to 100% losses on any crypto project... The program aims to get you to <b>10</b> Direct Referrals!</p>
	<p class="e"><a class="w" href="https://10x.day" target="_blank">Bootstrap Fund</a> is enabling <b>0</b> ambitious entrepreneurs to self-fund their businesses with passive income... The program aims to get you to <b>100</b> Direct Referrals!</p>
	<p class="e"><a class="w" href="https://10x.day" target="_blank">Bonus Bounty</a> has rewarded <b>0</b> freelance creatives with Paid Traffic for building epic 10X Bonuses... The program has a treasury of <b>$0.00</b> to be earnt!</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>Referrals<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Income<br><span class="k">This Week</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Crypto Rekt</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Bootstrap Fund</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Bonus Bounty</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>Referrals<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Income<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Crypto Rekt</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Bootstrap Fund</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Bonus Bounty</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🪴 Growth</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>Congratulations on <i>your</i> 10X Business!</b></p>
	<p class="e">Joining 10X means you are now your own boss...drive referrals, revenue &amp; engagement to grow these core business metrics!</p>
	<p class="e">Together we have a growing community of <b>1</b> subscribers, producing <b>$0.00</b> passive income, across <b>10</b> topics, with each user subscribing to an average of <b>2</b> topics.</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>Subscribed<br><span class="k">All Time</span></b></td>
				<td class="h"><b>Income<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Tech</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Crypto</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Marketing</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Design</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Business</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Startups</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Gaming</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Culture</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Finance</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Fashion</b></td>
				<td class="i">0</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>Count<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Count<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b>All Emails</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Subscribe</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Unsubscribe</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Growth Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Emails Sent</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Bounce</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Delivery Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Opens</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Open Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Click Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b>Revenue</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Buyers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Buyer Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Avg. Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Sponsor Revenue</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b>Engagement</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Points</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Avg. Points</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>All 5 Tasks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>All 5 Tasks Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Avg. Points Multiplier</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Active</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Inactive</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Active Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Level Up</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Level Down</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Level Up Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Avg. 10X Level</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b>Stats Email</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Opens</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Open Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Share Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Share Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b>News Email</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Opens</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Open Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Content Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Content Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Share Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Share Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Action Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Action Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Sponsor Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Sponsor Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Quote Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Quote Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Meme Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Meme Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b>Deals Email</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Opens</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Open Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Share Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Share Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Offer Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Offer Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b>Referrals</b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Organic</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Organic Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Paid</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Paid Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Non-Referred</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Non-Referred Rate</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>K Factor</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
		</tbody>
	</table>
	<p class="v" style="margin:3% 0 0 0;"><b>Life Time Value:</b></p>
	<p class="v">⏲️ 0 Avg. Days Subscribed</p>
	<p class="v">🕰️ 0 Subscribed for 100+ Days</p>
	<p class="v">💍 $0.00 LTV per user (all subscribers)</p>
	<p class="v">💎 $0.00 LTV per user (after 100+ Days)</p>
	<p class="v" style="margin:3% 0 0 0;"><b>Growth Velocity:</b></p>
	<p class="v">🕐 0 Days until first Share</p>
	<p class="v">🕑 0 Days until first Direct Referral</p>
	<p class="v">🕒 0 Days until first Network Referral</p>
	<p class="v">🕓 0 Days until first Direct Income</p>
	<p class="v">🕔 0 Days until first Network Income</p>
	<p class="v">🕕 0 Days until first Paid Traffic</p>
	<p class="v">🕖 0 Days until first Paid Referral</p>
	<p class="v">🕗 0 Days until first Revenue Reinvested</p>
	<p class="v">🕘 0 Days until first Deal Purchase</p>
	<p class="v">🕙 0 Days until returned to Active</p>
	<p class="v">🕚 0 Days until Points Multiplier 10X!</p>
	<p class="v">🕛 0 Days until LEVEL 10!</p>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">👍 Social</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="e" style="margin:0;"><b>More Signals, <i>Less Noise</i></b></p>
	<p class="e">Follow us on social media for the best daily news, deals &amp; memes!</p>
	<table class="f">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>Total<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Total<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<table class="j">
		<tbody>
			<tr class="g">
				<td class="h" style="text-align:left;">&nbsp;</td>
				<td class="h"><b>Count<br><span class="k">This Week</span></b></td>
				<td class="h"><b>Count<br><span class="k">All Time</span></b></td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">Twitter</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">Coub</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">YouTube</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">TikTok</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">Facebook</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">Instagram</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">LinkedIn</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">Pinterest</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">Reddit</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
			<tr class="g">
				<td class="z" colspan="3"><b><a class="y" href="https://10x.day" target="_blank">Giphy</a></b></td>
			</tr>
			<tr class="g">
				<td class="l"><b>Followers</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Posts</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Views</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Engagement</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Clicks</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Referrals</b></td>
				<td class="i">0</td>
				<td class="i">0</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Conversion</b></td>
				<td class="i">0%</td>
				<td class="i">0%</td>
			</tr>
			<tr class="g">
				<td class="l"><b>Income</b></td>
				<td class="i">$0.00</td>
				<td class="i">$0.00</td>
			</tr>
		</tbody>
	</table>
	<p class="n"><a class="o" href="https://10x.day" target="_blank">SHARE</a></p>
</td></tr></tbody></table></div>

<h1 class="a">🤓 Meta</h1>
<div class="b"><table class="c"><tbody><tr><td class="d">
	<p class="v" style="margin:3% 0 0 0;"><b>📈 <a class="w" href="https://10x.day" target="_blank">View Historical Stats Spreadsheet</a></b></p>
	<p class="v" style="margin:3% 0 0 0;"><b>{{RANDOM \`Hi\` \`Hello\` \`Hey\`}}:</b> [[firstname]]<br>
	<b>Date:</b> {{DATE \`YEAR-MONTH-DAY\`}}<br>
	<b>Time:</b> {{DATE \`HOUR:MINUTE:SECOND\`}}<br>
	<b>Campaign ID:</b> {{CONTACT \`campaign_id\`}}<br>
	<b>Message ID:</b> {{CONTACT \`message_id\`}}<br>
	<b>Subscriber ID:</b> {{CONTACT \`subscriber_id\`}}</p>
</td></tr></tbody></table></div>

			</td></tr></tbody></table>
		</td></tr></tbody></table>
	</td></tr></tbody></table>
</td></tr></tbody></table>
</body></html>
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
        "fromFieldId": "KxrZX" // "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "replyTo": {
        "fromFieldId": "KxrZX" // "K3KLa" // "oqRaG" // "KO8SL" // 10X Daily <hello@10x.day> // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/from-fields
      },
      "campaign": {
        "campaignId": "rRTkV" // "rJYER" // "LCJtj" // "Q1Oz0" // "10X Daily" subscriber list // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns
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
        "selectedCampaigns": ["rRTkV"], // ["rJYER"], // ["LCJtj"], // ["Q1Oz0"], // "10X Daily" subscriber list
        "selectedSegments": [],
        "selectedSuppressions": [],
        "excludedCampaigns": [],
        "excludedSegments": [],
        "selectedContacts": ["VKVmI6q"], //, "VK7KbWJ", "VK7Ba8m"], // test, me, stuart // ["VWqT16E"], // ["V5p8EtA"], // ["VohAb0F"], // Contact ID for email subscriber "test+5@10x.day" // {campaignId} = Q1Oz0 // curl -H "X-Auth-Token: api-key ____________" https://api.getresponse.com/v3/campaigns/Q1Oz0/contacts
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
