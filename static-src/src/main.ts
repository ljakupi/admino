import { createApp } from 'vue';
import { createPinia } from 'pinia';
import App from './App.vue';
import router from './router';
import { installUnauthorizedRedirect } from './services/session';

import './styles/tokens.css';
import './styles/reset.css';
import './styles/global.css';

const app = createApp(App);
app.use(createPinia());
app.use(router);
installUnauthorizedRedirect(router);
app.mount('#app');
