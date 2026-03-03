"""
SneakyGits — Extended fingerprint signatures.

Provides broader technology detection beyond the base fingerprinter:
frameworks, CMSes, CDNs, JS libraries, etc.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("krumpa.sneakygits.fingerprint_db")


class TechSignature:
    """A single technology signature."""

    __slots__ = ("name", "category", "header_patterns", "body_patterns", "cookie_patterns")

    def __init__(
        self,
        name: str,
        category: str,
        *,
        header_patterns: Optional[Dict[str, str]] = None,
        body_patterns: Optional[List[str]] = None,
        cookie_patterns: Optional[List[str]] = None,
    ) -> None:
        self.name = name
        self.category = category
        self.header_patterns = header_patterns or {}
        self.body_patterns = body_patterns or []
        self.cookie_patterns = cookie_patterns or []


# Extended signature database — modeled on Wappalyzer technology categories
TECH_SIGNATURES: List[TechSignature] = [
    # =====================================================================
    # Frameworks (Web)
    # =====================================================================
    TechSignature("Django", "framework", header_patterns={"X-Frame-Options": ".*", "Set-Cookie": "csrftoken"}, body_patterns=["csrfmiddlewaretoken"]),
    TechSignature("Rails", "framework", header_patterns={"X-Runtime": r"\d+\.\d+", "X-Request-Id": ".*"}, cookie_patterns=["_session_id"]),
    TechSignature("Laravel", "framework", header_patterns={"Set-Cookie": "laravel_session"}, body_patterns=["csrf-token"]),
    TechSignature("Express", "framework", header_patterns={"X-Powered-By": "Express"}),
    TechSignature("Spring", "framework", header_patterns={"X-Application-Context": ".*"}, cookie_patterns=["JSESSIONID"]),
    TechSignature("Spring Boot", "framework", body_patterns=["/actuator/health", "Whitelabel Error Page"]),
    TechSignature("ASP.NET", "framework", header_patterns={"X-AspNet-Version": ".*", "X-Powered-By": "ASP\\.NET"}, cookie_patterns=["ASP.NET_SessionId"]),
    TechSignature("ASP.NET Core", "framework", header_patterns={"X-Powered-By": "ASP\\.NET"}, body_patterns=["blazor", "_framework/blazor"]),
    TechSignature("Flask", "framework", header_patterns={"Server": "Werkzeug"}, body_patterns=["flask"]),
    TechSignature("FastAPI", "framework", body_patterns=["/openapi.json", "/docs", "/redoc"]),
    TechSignature("Next.js", "framework", header_patterns={"X-Powered-By": "Next\\.js"}, body_patterns=["_next/static", "__NEXT_DATA__"]),
    TechSignature("Nuxt.js", "framework", body_patterns=["_nuxt/", "__NUXT__"]),
    TechSignature("Gatsby", "framework", body_patterns=["gatsby-", "___gatsby"]),
    TechSignature("Remix", "framework", body_patterns=["__remix", "remix-run"]),
    TechSignature("SvelteKit", "framework", body_patterns=["__sveltekit", "svelte"]),
    TechSignature("Ember.js", "framework", body_patterns=["ember-", "data-ember"]),
    TechSignature("Meteor", "framework", body_patterns=["__meteor_runtime_config__"]),
    TechSignature("CakePHP", "framework", cookie_patterns=["CAKEPHP"]),
    TechSignature("CodeIgniter", "framework", cookie_patterns=["ci_session"]),
    TechSignature("Symfony", "framework", header_patterns={"X-Debug-Token": ".*"}, cookie_patterns=["PHPSESSID"]),
    TechSignature("Yii", "framework", cookie_patterns=["YII_CSRF_TOKEN", "_csrf"]),
    TechSignature("Zend", "framework", header_patterns={"X-Powered-By": ".*Zend.*"}),
    TechSignature("Play Framework", "framework", header_patterns={"Set-Cookie": "PLAY_SESSION"}),
    TechSignature("Gin", "framework", header_patterns={"X-Request-Id": ".*"}, body_patterns=["gin-gonic"]),
    TechSignature("Echo", "framework", body_patterns=["echo-go"]),
    TechSignature("Fiber", "framework", header_patterns={"X-Powered-By": "Fiber"}),
    TechSignature("Phoenix", "framework", cookie_patterns=["_csrf_token"]),
    TechSignature("Sinatra", "framework", header_patterns={"X-Powered-By": "Sinatra"}),
    TechSignature("Koa", "framework", header_patterns={"X-Powered-By": "koa"}),
    TechSignature("Hapi", "framework", body_patterns=["hapi"]),

    # =====================================================================
    # CMS
    # =====================================================================
    TechSignature("WordPress", "cms", body_patterns=["wp-content", "wp-includes", "wp-json"], cookie_patterns=["wordpress_"]),
    TechSignature("Drupal", "cms", header_patterns={"X-Generator": "Drupal"}, body_patterns=["sites/default/files"]),
    TechSignature("Joomla", "cms", body_patterns=["Joomla!", "/media/jui"], cookie_patterns=["joomla_"]),
    TechSignature("Magento", "cms", body_patterns=["Mage.Cookies", "/skin/frontend", "mage/"], cookie_patterns=["frontend"]),
    TechSignature("Shopify", "cms", body_patterns=["cdn.shopify.com", "Shopify.theme"]),
    TechSignature("Squarespace", "cms", body_patterns=["squarespace.com", "sqsp"]),
    TechSignature("Wix", "cms", body_patterns=["wix.com", "X-Wix-"]),
    TechSignature("Ghost", "cms", body_patterns=["ghost-", "ghost/"]),
    TechSignature("Typo3", "cms", body_patterns=["typo3", "TYPO3"]),
    TechSignature("PrestaShop", "cms", body_patterns=["prestashop", "PrestaShop"]),
    TechSignature("Contentful", "cms", body_patterns=["contentful"]),
    TechSignature("Strapi", "cms", body_patterns=["strapi"]),
    TechSignature("Hugo", "cms", body_patterns=["hugo-", "Generator\" content=\"Hugo"]),
    TechSignature("Jekyll", "cms", body_patterns=["jekyll", "Generator\" content=\"Jekyll"]),
    TechSignature("Webflow", "cms", body_patterns=["webflow.com"]),
    TechSignature("DNN (DotNetNuke)", "cms", body_patterns=["DNN", "DotNetNuke"], cookie_patterns=["dnn_IsMobile"]),
    TechSignature("Umbraco", "cms", body_patterns=["umbraco"]),
    TechSignature("Sitecore", "cms", cookie_patterns=["SC_ANALYTICS"]),
    TechSignature("AEM (Adobe Experience Manager)", "cms", body_patterns=["/etc.clientlibs", "/content/dam"]),

    # =====================================================================
    # Servers
    # =====================================================================
    TechSignature("Nginx", "server", header_patterns={"Server": "nginx"}),
    TechSignature("Apache", "server", header_patterns={"Server": "Apache"}),
    TechSignature("IIS", "server", header_patterns={"Server": "Microsoft-IIS"}),
    TechSignature("Caddy", "server", header_patterns={"Server": "Caddy"}),
    TechSignature("LiteSpeed", "server", header_patterns={"Server": "LiteSpeed"}),
    TechSignature("Tomcat", "server", header_patterns={"Server": "Apache-Coyote"}, body_patterns=["Apache Tomcat"]),
    TechSignature("Jetty", "server", header_patterns={"Server": "Jetty"}),
    TechSignature("Gunicorn", "server", header_patterns={"Server": "gunicorn"}),
    TechSignature("Uvicorn", "server", header_patterns={"Server": "uvicorn"}),
    TechSignature("Puma", "server", header_patterns={"X-Powered-By": "Puma"}),
    TechSignature("Kestrel", "server", header_patterns={"Server": "Kestrel"}),
    TechSignature("OpenResty", "server", header_patterns={"Server": "openresty"}),
    TechSignature("Cowboy", "server", header_patterns={"Server": "Cowboy"}),
    TechSignature("Tengine", "server", header_patterns={"Server": "Tengine"}),
    TechSignature("Cherokee", "server", header_patterns={"Server": "Cherokee"}),
    TechSignature("Lighttpd", "server", header_patterns={"Server": "lighttpd"}),
    TechSignature("WildFly", "server", header_patterns={"Server": "WildFly"}),
    TechSignature("WebLogic", "server", header_patterns={"Server": "WebLogic"}),
    TechSignature("WebSphere", "server", header_patterns={"Server": "WebSphere"}),

    # =====================================================================
    # CDN / Edge / Proxy
    # =====================================================================
    TechSignature("Cloudflare", "cdn", header_patterns={"Server": "cloudflare", "CF-RAY": ".*"}),
    TechSignature("AWS CloudFront", "cdn", header_patterns={"X-Amz-Cf-Id": ".*", "Via": ".*cloudfront.*"}),
    TechSignature("Fastly", "cdn", header_patterns={"X-Served-By": "cache-", "Via": ".*varnish.*"}),
    TechSignature("Akamai", "cdn", header_patterns={"X-Akamai-Transformed": ".*"}),
    TechSignature("Azure CDN", "cdn", header_patterns={"X-Azure-Ref": ".*"}),
    TechSignature("Google Cloud CDN", "cdn", header_patterns={"Via": ".*google.*"}),
    TechSignature("KeyCDN", "cdn", header_patterns={"Server": "keycdn"}),
    TechSignature("StackPath", "cdn", header_patterns={"X-HW": ".*"}),
    TechSignature("Incapsula", "cdn", header_patterns={"X-CDN": "Incapsula"}),
    TechSignature("Sucuri", "cdn", header_patterns={"Server": "Sucuri", "X-Sucuri-ID": ".*"}),
    TechSignature("Varnish", "proxy", header_patterns={"Via": ".*varnish.*", "X-Varnish": ".*"}),
    TechSignature("HAProxy", "proxy", header_patterns={"Server": "haproxy"}),
    TechSignature("Envoy", "proxy", header_patterns={"Server": "envoy", "X-Envoy-Upstream-Service-Time": ".*"}),
    TechSignature("Traefik", "proxy", header_patterns={"Server": "Traefik"}),
    TechSignature("Kong", "proxy", header_patterns={"Via": "kong", "Server": "kong"}),

    # =====================================================================
    # JS Libraries & Frameworks (client-side)
    # =====================================================================
    TechSignature("jQuery", "js-library", body_patterns=["jquery", "jQuery"]),
    TechSignature("React", "js-library", body_patterns=["react.production.min", "_reactRootContainer", "data-reactroot"]),
    TechSignature("Vue.js", "js-library", body_patterns=["vue.min.js", "vue.runtime", "v-cloak"]),
    TechSignature("Angular", "js-library", body_patterns=["ng-version", "ng-app", "angular.min.js"]),
    TechSignature("Bootstrap", "js-library", body_patterns=["bootstrap.min.css", "bootstrap.min.js", "class=\"container"]),
    TechSignature("Tailwind CSS", "css-framework", body_patterns=["tailwindcss", "class=\"flex", "class=\"grid"]),
    TechSignature("Lodash", "js-library", body_patterns=["lodash.min.js", "lodash.js"]),
    TechSignature("Moment.js", "js-library", body_patterns=["moment.min.js"]),
    TechSignature("D3.js", "js-library", body_patterns=["d3.min.js", "d3.js"]),
    TechSignature("Three.js", "js-library", body_patterns=["three.min.js"]),
    TechSignature("Chart.js", "js-library", body_patterns=["chart.min.js", "chart.js"]),
    TechSignature("Alpine.js", "js-library", body_patterns=["x-data", "alpine.js"]),
    TechSignature("HTMX", "js-library", body_patterns=["htmx.min.js", "hx-get", "hx-post"]),
    TechSignature("Stimulus", "js-library", body_patterns=["data-controller", "stimulus"]),
    TechSignature("Turbo", "js-library", body_patterns=["turbo-frame", "data-turbo"]),
    TechSignature("Axios", "js-library", body_patterns=["axios.min.js"]),
    TechSignature("Socket.IO", "js-library", body_patterns=["socket.io.min.js", "socket.io.js"]),
    TechSignature("Underscore.js", "js-library", body_patterns=["underscore.min.js", "underscore-min.js"]),
    TechSignature("Backbone.js", "js-library", body_patterns=["backbone.min.js", "backbone-min.js"]),
    TechSignature("Knockout.js", "js-library", body_patterns=["knockout-", "ko.applyBindings"]),
    TechSignature("Polymer", "js-library", body_patterns=["polymer.html", "polymer-element"]),
    TechSignature("Preact", "js-library", body_patterns=["preact"]),
    TechSignature("Solid.js", "js-library", body_patterns=["solid-js"]),
    TechSignature("Lit", "js-library", body_patterns=["lit-element", "lit-html"]),

    # =====================================================================
    # Security / WAF
    # =====================================================================
    TechSignature("Helmet", "security", header_patterns={"X-DNS-Prefetch-Control": ".*", "X-Content-Type-Options": "nosniff"}),
    TechSignature("ModSecurity", "waf", header_patterns={"Server": ".*ModSecurity.*"}),
    TechSignature("AWS WAF", "waf", header_patterns={"X-AMZ-WAF-Action": ".*"}),
    TechSignature("Imperva", "waf", header_patterns={"X-CDN": "Imperva"}),
    TechSignature("F5 BIG-IP", "waf", header_patterns={"Server": "BigIP", "Set-Cookie": "BIGipServer"}),
    TechSignature("Barracuda WAF", "waf", header_patterns={"Server": "Barracuda"}),
    TechSignature("Citrix NetScaler", "waf", header_patterns={"Via": ".*NS-CACHE.*"}, cookie_patterns=["NSC_", "ns_"]),

    # =====================================================================
    # Analytics / Tracking
    # =====================================================================
    TechSignature("Google Analytics", "analytics", body_patterns=["google-analytics.com/analytics.js", "gtag.js", "UA-"]),
    TechSignature("Google Tag Manager", "analytics", body_patterns=["googletagmanager.com", "GTM-"]),
    TechSignature("Matomo / Piwik", "analytics", body_patterns=["matomo.js", "piwik.js"]),
    TechSignature("Hotjar", "analytics", body_patterns=["hotjar.com", "static.hotjar.com"]),
    TechSignature("Segment", "analytics", body_patterns=["analytics.js", "cdn.segment.com"]),
    TechSignature("Mixpanel", "analytics", body_patterns=["mixpanel.com", "mixpanel.init"]),
    TechSignature("Heap", "analytics", body_patterns=["heap-", "heapanalytics.com"]),
    TechSignature("Sentry", "monitoring", body_patterns=["sentry.io", "Sentry.init"]),
    TechSignature("New Relic", "monitoring", body_patterns=["newrelic.com", "NREUM"]),
    TechSignature("Datadog", "monitoring", body_patterns=["datadoghq.com", "DD_RUM"]),

    # =====================================================================
    # Authentication / Identity
    # =====================================================================
    TechSignature("Auth0", "auth", body_patterns=["auth0.com", "auth0-lock"]),
    TechSignature("Okta", "auth", body_patterns=["okta.com", "okta-"]),
    TechSignature("Firebase Auth", "auth", body_patterns=["firebase", "firebaseapp.com"]),
    TechSignature("Keycloak", "auth", body_patterns=["keycloak", "/auth/realms/"]),
    TechSignature("OAuth2", "auth", body_patterns=["oauth2", "response_type=code", "grant_type="]),
    TechSignature("SAML", "auth", body_patterns=["SAMLRequest", "SAMLResponse"]),
    TechSignature("OpenID Connect", "auth", body_patterns=["openid-connect", ".well-known/openid-configuration"]),

    # =====================================================================
    # Programming Languages (runtime detection)
    # =====================================================================
    TechSignature("PHP", "language", header_patterns={"X-Powered-By": "PHP", "Server": ".*PHP.*"}, cookie_patterns=["PHPSESSID"]),
    TechSignature("Java", "language", cookie_patterns=["JSESSIONID"]),
    TechSignature("Python", "language", header_patterns={"Server": "(?:Werkzeug|gunicorn|uvicorn|CherryPy|TwistedWeb)"}),
    TechSignature("Ruby", "language", header_patterns={"X-Powered-By": "Phusion Passenger"}, cookie_patterns=["_session_id"]),
    TechSignature("Node.js", "language", header_patterns={"X-Powered-By": "Express"}),
    TechSignature("Go", "language", header_patterns={"Server": "(?:Caddy|Gin|Fiber)"}),
    TechSignature("Perl", "language", header_patterns={"Server": ".*Perl.*"}),

    # =====================================================================
    # Databases (indirect detection)
    # =====================================================================
    TechSignature("MongoDB", "database", body_patterns=["ObjectId(", "mongodb://"]),
    TechSignature("Redis", "database", body_patterns=["redis://", "Redis"]),
    TechSignature("Elasticsearch", "database", body_patterns=["elasticsearch", "lucene_version"]),
    TechSignature("PostgreSQL", "database", body_patterns=["psycopg2", "pg_catalog"]),

    # =====================================================================
    # E-Commerce
    # =====================================================================
    TechSignature("WooCommerce", "ecommerce", body_patterns=["woocommerce", "wc-cart"]),
    TechSignature("BigCommerce", "ecommerce", body_patterns=["bigcommerce"]),
    TechSignature("OpenCart", "ecommerce", body_patterns=["opencart", "catalog/view"]),

    # =====================================================================
    # API Gateways
    # =====================================================================
    TechSignature("AWS API Gateway", "api-gateway", header_patterns={"X-Amzn-Requestid": ".*", "X-Amz-Apigw-Id": ".*"}),
    TechSignature("Azure API Management", "api-gateway", header_patterns={"Ocp-Apim-Subscription-Key": ".*"}),
    TechSignature("Apigee", "api-gateway", header_patterns={"X-Apigee-Message-Id": ".*"}),
    TechSignature("Tyk", "api-gateway", header_patterns={"X-Tyk-Gateway": ".*"}),

    # =====================================================================
    # Hosting / PaaS
    # =====================================================================
    TechSignature("Heroku", "paas", header_patterns={"Via": ".*heroku.*", "Server": ".*heroku.*"}),
    TechSignature("Netlify", "paas", header_patterns={"Server": "Netlify", "X-Nf-Request-Id": ".*"}),
    TechSignature("Vercel", "paas", header_patterns={"Server": "Vercel", "X-Vercel-Id": ".*"}),
    TechSignature("GitHub Pages", "paas", header_patterns={"Server": "GitHub.com"}),
    TechSignature("AWS S3", "paas", header_patterns={"Server": "AmazonS3", "X-Amz-Request-Id": ".*"}),
    TechSignature("Azure Blob", "paas", header_patterns={"Server": ".*Blob.*", "X-Ms-Request-Id": ".*"}),
    TechSignature("Render", "paas", header_patterns={"Server": "Render"}),
    TechSignature("Railway", "paas", body_patterns=["railway.app"]),
    TechSignature("Fly.io", "paas", header_patterns={"Server": "Fly", "Fly-Request-Id": ".*"}),

    # =====================================================================
    # Miscellaneous / DevTools
    # =====================================================================
    TechSignature("Webpack", "build-tool", body_patterns=["webpackJsonp", "webpack"]),
    TechSignature("Vite", "build-tool", body_patterns=["/@vite/", "vite"]),
    TechSignature("Parcel", "build-tool", body_patterns=["parcelRequire"]),
    TechSignature("RequireJS", "build-tool", body_patterns=["requirejs", "require.config"]),
    TechSignature("GraphQL", "api", body_patterns=["graphql", "__schema"]),
    TechSignature("REST API", "api", body_patterns=["swagger", "openapi"]),
    TechSignature("gRPC-Web", "api", header_patterns={"Content-Type": "application/grpc-web"}),
    TechSignature("WebSocket", "protocol", body_patterns=["new WebSocket", "ws://", "wss://"]),
    TechSignature("Service Worker", "pwa", body_patterns=["serviceWorker.register", "sw.js"]),
    TechSignature("PWA", "pwa", body_patterns=["manifest.json", "web-app-manifest"]),
    TechSignature("AMP", "framework", body_patterns=["amp-", "cdn.ampproject.org"]),
    TechSignature("Cloudflare Workers", "serverless", header_patterns={"CF-Worker": ".*"}),
    TechSignature("AWS Lambda", "serverless", header_patterns={"X-Amz-Function-Name": ".*"}),
    TechSignature("Recaptcha", "security", body_patterns=["recaptcha", "grecaptcha"]),
    TechSignature("hCaptcha", "security", body_patterns=["hcaptcha.com"]),
    TechSignature("Turnstile", "security", body_patterns=["challenges.cloudflare.com/turnstile"]),

    # =====================================================================
    # Caching
    # =====================================================================
    TechSignature("Memcached", "cache", header_patterns={"X-Cache-Engine": ".*memcache.*"}),
    TechSignature("Redis Cache", "cache", header_patterns={"X-Cache-Engine": ".*redis.*"}),
    TechSignature("Squid", "proxy", header_patterns={"Server": "squid", "Via": ".*squid.*"}),

    # =====================================================================
    # Email / Marketing
    # =====================================================================
    TechSignature("Mailchimp", "marketing", body_patterns=["mailchimp.com", "mc.js"]),
    TechSignature("SendGrid", "email", header_patterns={"X-SG-EID": ".*"}),
    TechSignature("Intercom", "marketing", body_patterns=["intercom.com", "intercomSettings"]),
    TechSignature("Drift", "marketing", body_patterns=["drift.com", "driftt.com"]),
    TechSignature("HubSpot", "marketing", body_patterns=["hubspot.com", "hs-scripts"]),
    TechSignature("Zendesk", "support", body_patterns=["zendesk.com", "zE("]),

    # =====================================================================
    # Payment / Fintech
    # =====================================================================
    TechSignature("Stripe", "payment", body_patterns=["js.stripe.com", "Stripe("]),
    TechSignature("PayPal", "payment", body_patterns=["paypal.com/sdk", "paypalobjects"]),
    TechSignature("Braintree", "payment", body_patterns=["braintreegateway.com"]),
    TechSignature("Square", "payment", body_patterns=["squareup.com", "squareCDN"]),
    TechSignature("Adyen", "payment", body_patterns=["adyen.com", "adyenCheckout"]),

    # =====================================================================
    # Container / Orchestration (indirect)
    # =====================================================================
    TechSignature("Kubernetes", "orchestration", header_patterns={"Server": ".*kube.*"}),
    TechSignature("Docker", "container", body_patterns=["docker", "Docker"]),
    TechSignature("Istio", "service-mesh", header_patterns={"X-Envoy-Decorator-Operation": ".*"}),

    # =====================================================================
    # Message Queues (indirect)
    # =====================================================================
    TechSignature("RabbitMQ", "message-queue", body_patterns=["rabbitmq"]),
    TechSignature("Kafka", "message-queue", body_patterns=["kafka"]),

    # =====================================================================
    # Additional JS / UI Libraries
    # =====================================================================
    TechSignature("Svelte", "js-library", body_patterns=["svelte", "__svelte"]),
    TechSignature("Mithril.js", "js-library", body_patterns=["mithril", "m.render"]),
    TechSignature("Handlebars", "template-engine", body_patterns=["Handlebars.compile", "handlebars.min.js"]),
    TechSignature("Mustache", "template-engine", body_patterns=["mustache.min.js", "Mustache.render"]),
    TechSignature("EJS", "template-engine", body_patterns=["ejs.min.js"]),
    TechSignature("Pug", "template-engine", body_patterns=["pug"]),
    TechSignature("Highcharts", "js-library", body_patterns=["highcharts.com", "Highcharts.chart"]),
    TechSignature("Leaflet", "js-library", body_patterns=["leaflet.js", "L.map"]),
    TechSignature("Mapbox", "js-library", body_patterns=["mapbox.com", "mapboxgl"]),
    TechSignature("Swiper", "js-library", body_patterns=["swiper-", "swiper.min.js"]),
    TechSignature("Slick", "js-library", body_patterns=["slick.min.js", "slick-slider"]),
    TechSignature("Select2", "js-library", body_patterns=["select2.min.js", "select2"]),
    TechSignature("DataTables", "js-library", body_patterns=["dataTables", "datatables.min.js"]),
    TechSignature("TinyMCE", "js-library", body_patterns=["tinymce.min.js", "tinymce"]),
    TechSignature("CKEditor", "js-library", body_patterns=["ckeditor.js", "CKEDITOR"]),
    TechSignature("Quill", "js-library", body_patterns=["quill.min.js", "ql-editor"]),
    TechSignature("Tippy.js", "js-library", body_patterns=["tippy", "tippy.js"]),
    TechSignature("Popper.js", "js-library", body_patterns=["popper.min.js", "Popper"]),
    TechSignature("Anime.js", "js-library", body_patterns=["anime.min.js"]),
    TechSignature("GSAP", "js-library", body_patterns=["gsap.min.js", "gsap"]),
    TechSignature("Lottie", "js-library", body_patterns=["lottie", "lottie-player"]),
    TechSignature("Plyr", "js-library", body_patterns=["plyr.js", "plyr.min.js"]),
    TechSignature("Video.js", "js-library", body_patterns=["video.js", "video-js"]),
    TechSignature("Cropper.js", "js-library", body_patterns=["cropper.min.js"]),
    TechSignature("Flatpickr", "js-library", body_patterns=["flatpickr.min.js", "flatpickr"]),
    TechSignature("FullCalendar", "js-library", body_patterns=["fullcalendar.min.js"]),
]


class FingerprintDb:
    """Match HTTP responses against extended tech signatures."""

    def __init__(self, signatures: Optional[List[TechSignature]] = None) -> None:
        self._signatures = signatures or TECH_SIGNATURES

    def detect(
        self,
        *,
        headers: Optional[Dict[str, str]] = None,
        body: str = "",
        cookies: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, str]]:
        """Return list of detected technologies as {name, category, evidence}."""
        headers = headers or {}
        cookies = cookies or {}
        detections: List[Dict[str, str]] = []

        for sig in self._signatures:
            evidence = self._match(sig, headers, body, cookies)
            if evidence:
                detections.append({
                    "name": sig.name,
                    "category": sig.category,
                    "evidence": evidence,
                })

        return detections

    @staticmethod
    def _match(
        sig: TechSignature,
        headers: Dict[str, str],
        body: str,
        cookies: Dict[str, str],
    ) -> Optional[str]:
        # Check headers
        for hdr_name, pattern in sig.header_patterns.items():
            for actual_name, actual_value in headers.items():
                if actual_name.lower() == hdr_name.lower():
                    if re.search(pattern, actual_value, re.IGNORECASE):
                        return f"header {hdr_name}={actual_value}"

        # Check body
        body_lower = body.lower()
        for pattern in sig.body_patterns:
            if pattern.lower() in body_lower:
                return f"body contains '{pattern}'"

        # Check cookies
        cookie_str = " ".join(f"{k}={v}" for k, v in cookies.items())
        for pattern in sig.cookie_patterns:
            if pattern.lower() in cookie_str.lower():
                return f"cookie matches '{pattern}'"

        return None
