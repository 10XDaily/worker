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
// const GR_API = 'https://api.getresponse.com/v3/';
// const GR_API_NEWSLETTERS = "newsletters" // https://apireference.getresponse.com/#operation/createNewsletter
router.get("/newsletter", async request => {
  console.log("newsletter logs");
  
  // temporarily trying this weather app example
  // https://developers.cloudflare.com/workers/examples/geolocation-app-weather/
  let endpoint = 'https://api.waqi.info/feed/geo:';
  const token = '3a27aceb859b4fc0554b47699f61b78e1331e799'; //Use a token from https://aqicn.org/api/
  let html_style = `body{padding:6em; font-family: sans-serif;} h1{color:#f6821f}`;
  let html_content = '<h1>Weather 🌦</h1>';

  let latitude = request.cf.latitude;
  let longitude = request.cf.longitude;
  endpoint += `${latitude};${longitude}/?token=${token}`;
  const init = {
    headers: {
      'content-type': 'application/json;charset=UTF-8',
    },
  };

  const response = await fetch(endpoint, init);
  const content = await response.json();

  html_content += `<p>This is a demo using Workers geolocation data. </p>`;
  html_content += `You are located at: ${latitude},${longitude}.</p>`;
  html_content += `<p>Based off sensor data from <a href="${content.data.url}">${content.data.city.name}</a>:</p>`;
  html_content += `<p>The AQI level is: ${content.data.aqi}.</p>`;

  let html = `
<!DOCTYPE html>
<head>
  <title>Geolocation: Weather</title>
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
