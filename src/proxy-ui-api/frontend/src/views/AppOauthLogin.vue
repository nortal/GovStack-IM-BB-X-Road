<!--
   The MIT License
   Copyright (c) 2019- Nordic Institute for Interoperability Solutions (NIIS)
   Copyright (c) 2018 Estonian Information System Authority (RIA),
   Nordic Institute for Interoperability Solutions (NIIS), Population Register Centre (VRK)
   Copyright (c) 2015-2017 Estonian Information System Authority (RIA), Population Register Centre (VRK)

   Permission is hereby granted, free of charge, to any person obtaining a copy
   of this software and associated documentation files (the "Software"), to deal
   in the Software without restriction, including without limitation the rights
   to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
   copies of the Software, and to permit persons to whom the Software is
   furnished to do so, subject to the following conditions:

   The above copyright notice and this permission notice shall be included in
   all copies or substantial portions of the Software.

   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
   IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
   AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
   LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
   OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
   THE SOFTWARE.
 -->
<template>
  <v-container fluid fill-height class="login-view-wrap">
    <alerts-container class="alerts" />
    <div class="graphics">
      <v-img
        :src="require('../assets/xroad7_large.svg')"
        height="195"
        width="144"
        max-height="195"
        max-width="144"
        class="xrd-logo"
      ></v-img>
    </div>
  </v-container>
</template>

<script lang="ts">
import Vue, { VueConstructor } from 'vue';
import { Permissions, RouteName } from '@/global';
import { ValidationObserver } from 'vee-validate';
import { AxiosError } from 'axios';
import { mapActions, mapState } from 'pinia';
import { useUser } from '@/store/modules/user';
import { useSystemStore } from '@/store/modules/system';
import { useNotifications } from '@/store/modules/notifications';
import AlertsContainer from '@/components/ui/AlertsContainer.vue';

export default (
  Vue as VueConstructor<
    Vue & {
      $refs: {
        form: InstanceType<typeof ValidationObserver>;
      };
    }
  >
).extend({
  name: 'OauthLogin',
  components: { AlertsContainer },
  data() {
    return {
      loading: false as boolean,
    };
  },
  computed: {
    ...mapState(useUser, [
      'hasPermission',
      'firstAllowedTab',
      'hasInitState',
      'needsInitialization',
    ]),
    isDisabled() {
      if (this.loading) {
        return true;
      }
      return false;
    },
  },
  mounted() {
    this.oauthLogin();
  },
  methods: {
    ...mapActions(useUser, [
      'fetchInitializationStatus',
      'logoutUser',
      'fetchUserData',
      'fetchCurrentSecurityServer',
      'clearAuth',
      'setOauthLoginSuccessful',
    ]),
    ...mapActions(useSystemStore, [
      'fetchSecurityServerVersion',
      'fetchSecurityServerNodeType',
      'clearSystemStore',
    ]),
    ...mapActions(useNotifications, [
      'showError',
      'showErrorMessage',
      'clearErrorNotifications',
    ]),

    async oauthLogin() {
      this.loading = true;
      this.setOauthLoginSuccessful();
      try {
        await this.fetchUserData();
        await this.fetchInitializationData(); // Used to be inside fetchUserData()
        await this.fetchSecurityServerVersion();
        await this.fetchSecurityServerNodeType();
      } catch (error) {
        this.showError(error as AxiosError);
      }
      this.loading = false;
    },

    async fetchInitializationData() {
      const redirectToLogin = async () => {
        // Logout without page refresh
        await this.logoutUser(false);
        await this.$router.push({ name: RouteName.Login });
      };

      await this.fetchInitializationStatus();
      await this.fetchSecurityServerNodeType();
      if (!this.hasInitState) {
        this.showErrorMessage(
          this.$t('initialConfiguration.noInitializationStatus'),
        );
        await redirectToLogin();
      } else if (this.needsInitialization) {
        // Check if the user has permission to initialize the server
        if (!this.hasPermission(Permissions.INIT_CONFIG)) {
          await redirectToLogin();
          throw new Error(
            this.$t('initialConfiguration.noPermission') as string,
          );
        }
        await this.$router.replace({ name: RouteName.InitialConfiguration });
      } else {
        // No need to initialise, proceed to "main view"
        await this.fetchCurrentSecurityServer();
        await this.$router.replace({
          name: this.firstAllowedTab.to.name,
        });
      }
    },
  },
});
</script>

<style lang="scss" scoped>
@import '~styles/colors';

.alerts {
  top: 40px;
  left: 0;
  right: 0;
  margin-left: auto;
  margin-right: auto;
  z-index: 100;
  position: absolute;
}

.graphics {
  height: 100%;
  width: 40%;
  max-width: 576px; // width of the background image
  background-image: url('../assets/background.png');
  background-size: cover;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.login-view-wrap {
  background-color: white;
  padding: 0;
}
</style>
