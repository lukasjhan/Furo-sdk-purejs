console.log(
  "This is a browser feature intended for developers. Do not enter or paste code which you don't understand. It may allow attackers to steal your information or impersonate you.\nSee https://en.wikipedia.org/wiki/Self-XSS for more details"
);

let FuroClientId;
let FuroRedirectUri;
let FuroPublicApikey;
let modalContainer;

function initLoginModal() {
  modalContainer = document.createElement('div');
  modalContainer.id = 'furo-login-modal';
  modalContainer.style.display = 'none';
  modalContainer.style.position = 'fixed';
  modalContainer.style.alignItems = 'center';
  modalContainer.style.justifyContent = 'center';
  modalContainer.style.top = '0';
  modalContainer.style.left = '0';
  modalContainer.style.width = '100%';
  modalContainer.style.height = '100%';
  modalContainer.style.backgroundColor = 'rgba(0, 0, 0, 0.5)';
  modalContainer.style.justifyContent = 'center';
  modalContainer.style.alignItems = 'center';
  modalContainer.style.zIndex = '1000';

  // Create the modal content
  const modalContent = document.createElement('div');
  modalContent.style.backgroundColor = '#fff';
  modalContent.style.width = '500px';
  modalContent.style.height = 'fit-content';
  modalContent.style.margin;
  modalContent.style.padding = '20px';
  modalContent.style.borderRadius = '5px';
  modalContent.style.boxShadow = '0px 0px 10px rgba(0, 0, 0, 0.2)';
  modalContent.innerHTML = `
  <h2>Welcome to Furo</h2>
  <form id="loginForm">
    <label for="email">Email:</label>
    <input type="email" id="furo-email" name="email" required>
    <br>
    <label for="password">Password:</label>
    <input type="password" id="furo-password" name="password" required>
    <br>
    <button type="submit">Login</button>
  </form>
`;

  // Append the modal components to the document body
  document.body.appendChild(modalContainer);
  modalContainer.appendChild(modalContent);
}

async function init(options) {
  const { clientId, redirectUri, apikey } = options;
  FuroClientId = clientId;
  FuroRedirectUri = redirectUri;
  FuroPublicApikey = apikey;

  initLoginModal();

  try {
    if (await handleRedirectCallback()) {
      console.log('login success');
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

function encodeBase64(base64String) {
  return btoa(base64String);
}

const API_SERVER = 'https://api.furo.one';
const AUTH_DOMAIN = 'https://auth.furo.one';
const CODE_RE = /[?&]code=[^&]+/;

function getFuroLoginURL() {
  if (!FuroClientId)
    throw new Error('ClientId needed to get the Furo login url');

  const baseUrl = `${AUTH_DOMAIN}/login/${FuroClientId}`;
  if (FuroRedirectUri)
    return `${baseUrl}?redirect_uri=${encodeURIComponent(FuroRedirectUri)}`;
  else return baseUrl;
}

function loginWithRedirect() {
  const loginUrl = getFuroLoginURL();
  window.location.href = loginUrl;
}

async function loginWithPopup() {
  console.log('popup!');
  modalContainer.style.display = 'flex';
  return new Promise((resolve) => {
    document
      .getElementById('loginForm')
      .addEventListener('submit', async function (e) {
        e.preventDefault();

        // Get API key
        const BasicAuth = btoa(`${FuroClientId}:${FuroPublicApikey}`);

        // Get email and password values
        const email = document.getElementById('furo-email').value;
        const password = document.getElementById('furo-password').value;

        // Create an object with email and password
        const data = {
          email: email,
          password: password,
          projectId: FuroClientId,
          requireExtraCode: false,
        };

        console.log(data);

        // Make a POST request to your authentication endpoint
        const response = await fetch(`${API_SERVER}/passwords/authenticate`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Basic ${BasicAuth}`,
          },
          body: JSON.stringify(data),
        }).then((res) => res.json());
        console.log(response);
        closeLoginPopup();
        resolve(response);
      });
  });
}

function closeLoginPopup() {
  console.log('close popup!');
  modalContainer.style.display = 'none';
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

  console.log('Handle Login Start');

  const params = new URLSearchParams(url);
  const code = params.get('code');
  const data = await fetch(`https://api.furo.one/sessions/code/authenticate`, {
    method: 'POST',
    body: JSON.stringify({ code }),
    headers: {
      'Content-Type': 'application/json',
    },
  }).then((res) => res.json());

  const { access_token: accessToken, refresh_token: refreshToken } = data;

  const base64Payload = accessToken.split('.')[1];
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
  const data = await fetch(`https://api.furo.one/sessions/token/refresh`, {
    method: 'POST',
    body: JSON.stringify({
      accessToken,
    }),
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${refreshToken}`,
    },
  }).then((res) => res.json());
  const { access_token, refresh_token } = data;
  localStorage.setItem(`furo-${FuroClientId}-token`, access_token);
  localStorage.setItem(`furo-${FuroClientId}-refresh`, refresh_token);
  return { access_token, refresh_token };
}

window.Furo = {
  AUTH_DOMAIN,
  init,
  loginWithRedirect,
  loginWithPopup,
  closeLoginPopup,
  handleRedirectCallback,
  logout,
  getUser,
  refreshTokenSilently,
};
