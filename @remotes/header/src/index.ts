import { createRemoteApp } from '@docplanner/remotejs/app';
import {createI18n, useI18n} from "vue-i18n";
import {createApp} from "vue";

export default createRemoteApp(() => {
    const app = createApp({});

    const i18n = createI18n({
        legacy: false,
        locale: 'pl',
        messages: { pl: {} },
    });

    app.use(i18n);

    const { t } = useI18n();

    t('dpw_menu_notifications')
});
