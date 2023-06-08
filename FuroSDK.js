console.log(
  "This is a browser feature intended for developers. Do not enter or paste code which you don't understand. It may allow attackers to steal your information or impersonate you.\nSee https://en.wikipedia.org/wiki/Self-XSS for more details"
);

let FuroClientId;
let FuroRedirectUri;

async function init(options) {
  const { clientId, redirectUri } = options;
  FuroClientId = clientId;
  FuroRedirectUri = redirectUri;

  try {
    if (await handleRedirectCallback()) {
      console.log("login success");
    }

    const user = await getUser();
    if (!user) {
      logout();
    }
    return user;
  } catch (error) {
    console.error(error);
    try {
      const { access_token, refresh_token } = await refreshTokenSilently();
      if (access_token && refresh_token) init(options);
    } catch (error) {
      console.error(error);
    }
  }
}

function decodeBase64(base64String) {
  return atob(base64String);
}

const AUTH_DOMAIN = "https://auth.furo.one";
const CODE_RE = /[?&]code=[^&]+/;

function getFuroLoginURL() {
  if (!FuroClientId)
    throw new Error("ClientId needed to get the Furo login url");

  const baseUrl = `${AUTH_DOMAIN}/login/${FuroClientId}`;
  if (FuroRedirectUri)
    return `${baseUrl}?redirect_uri=${encodeURIComponent(FuroRedirectUri)}`;
  else return baseUrl;
}

function loginWithRedirect() {
  const loginUrl = getFuroLoginURL();
  window.location.href = loginUrl;
}

function hasAuthParams(searchParams = window.location.search) {
  return CODE_RE.test(searchParams);
}

function logout() {
  localStorage.removeItem(`furo-${FuroClientId}-token`);
  sessionStorage.removeItem(`furo-${FuroClientId}-token`);
}

async function handleRedirectCallback(url = window.location.search) {
  if (!hasAuthParams(url)) return false;

  console.log("Handle Login Start");

  const params = new URLSearchParams(url);
  const code = params.get("code");
  const data = await fetch(`https://api.furo.one/sessions/code/authenticate`, {
    method: "POST",
    body: JSON.stringify({ code }),
    headers: {
      "Content-Type": "application/json",
    },
  }).then((res) => res.json());

  const { access_token: accessToken, refresh_token: refreshToken } = data;

  const base64Payload = accessToken.split(".")[1];
  const { pid } = JSON.parse(decodeBase64(base64Payload));
  if (!pid) return false;

  localStorage.setItem(`furo-${FuroClientId}-token`, accessToken);
  localStorage.setItem(`furo-${FuroClientId}-refresh`, refreshToken);

  return true;
}

async function getUser() {
  const accessToken = localStorage.getItem(`furo-${FuroClientId}-token`);
  if (!accessToken) return null;

  const response = await fetch(`https://api.furo.one/users/me`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  return response.json();
}

async function refreshTokenSilently() {
  const refreshToken = localStorage.getItem(`furo-${FuroClientId}-refresh`);
  if (!refreshToken) return null;
  const accessToken = localStorage.getItem(`furo-${FuroClientId}-token`);
  if (!accessToken) return null;
  const { data } = await axios.post(
    `/sessions/token/refresh`,
    {
      accessToken,
    },
    {
      headers: { Authorization: `Bearer ${refreshToken}` },
    }
  );
  const { access_token, refresh_token } = data;
  localStorage.setItem(`furo-${FuroClientId}-token`, access_token);
  localStorage.setItem(`furo-${FuroClientId}-refresh`, refresh_token);
  return { access_token, refresh_token };
}

window.Furo = {
  AUTH_DOMAIN,
  init,
  loginWithRedirect,
  handleRedirectCallback,
  logout,
  getUser,
  refreshTokenSilently,
};
