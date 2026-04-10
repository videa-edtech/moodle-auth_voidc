<?php
// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Resource Owner Password Credentials Grant login flow.
 *
 * @package auth_voidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

namespace auth_voidc\loginflow;

use auth_voidc\utils;

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/voidc/lib.php');

/**
 * Login flow for the oauth2 resource owner credentials grant.
 */
class rocreds extends base {
    /**
     * Check for an existing user object.
     *
     * @param string $o356username
     *
     * @return string If there is an existing user object, return the username associated with it.
     *                If there is no existing user object, return the original username.
     */
    protected function check_objects($username) {
        return $username;
    }

    /**
     * Provides a hook into the login page.
     *
     * @param stdClass $frm Form object.
     * @param stdClass $user User object.
     * @return bool
     */
    public function loginpage_hook(&$frm, &$user) {
        global $DB;

        if (empty($frm)) {
            $frm = data_submitted();
        }
        if (empty($frm)) {
            return true;
        }

        $username = $frm->username;
        $password = $frm->password;
        $auth = 'voidc';

        $username = $this->check_objects($username);
        if ($username !== $frm->username) {
            $success = $this->user_login($username, $password);
            if ($success === true) {
                $existinguser = $DB->get_record('user', ['username' => $username]);
                if (!empty($existinguser)) {
                    $user = $existinguser;
                    return true;
                }
            }
        }

        $autoappend = get_config('auth_voidc', 'autoappend');
        if (empty($autoappend)) {
            // If we're not doing autoappend, just let things flow naturally.
            return true;
        }

        $existinguser = $DB->get_record('user', ['username' => $username]);
        if (!empty($existinguser)) {
            // We don't want to prevent access to existing accounts.
            return true;
        }

        $username .= $autoappend;
        $success = $this->user_login($username, $password);
        if ($success !== true) {
            // No o365 user, continue normally.
            return false;
        }

        $existinguser = $DB->get_record('user', ['username' => $username]);
        if (!empty($existinguser)) {
            $user = $existinguser;
            return true;
        }

        // The user is authenticated but user creation may be disabled.
        if (!empty($CFG->authpreventaccountcreation)) {
            $failurereason = AUTH_LOGIN_UNAUTHORISED;

            // Trigger login failed event.
            $event = \core\event\user_login_failed::create(['other' => ['username' => $username,
                    'reason' => $failurereason]]);
            $event->trigger();

            debugging('[client '.getremoteaddr()."]  $CFG->wwwroot  Unknown user, can not create new accounts:  $username  ".
                $_SERVER['HTTP_USER_AGENT']);

            return false;
        }

        $user = create_user_record($username, $password, $auth);
        return true;
    }

    /**
     * This is the primary method that is used by the authenticate_user_login() function in moodlelib.php.
     *
     * @param string $username The username (with system magic quotes)
     * @param string $password The password (with system magic quotes)
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password = null) {
        global $DB, $CFG;

        $authparams = ['code' => ''];

        $oidcusername = $username;
        $oidctoken = $DB->get_records('auth_voidc_token', ['username' => $username]);
        if (!empty($oidctoken)) {
            $oidctoken = array_shift($oidctoken);
            if (!empty($oidctoken) && !empty($oidctoken->oidcusername)) {
                $oidcusername = $oidctoken->oidcusername;
            }
        }

        // If we already have a token for this user, prefer its client so we hit the
        // IdP that issued it. Otherwise try each enabled client until one accepts the
        // credentials - the password grant has no UI for the user to pick a provider.
        $clientsoftry = [];
        if (!empty($oidctoken) && !empty($oidctoken->clientid)) {
            $known = auth_voidc_get_client((int) $oidctoken->clientid);
            if (!empty($known) && !empty($known->enabled)) {
                $clientsoftry[(int) $known->id] = $known;
            }
        }
        foreach (auth_voidc_get_enabled_clients() as $c) {
            if (!isset($clientsoftry[(int) $c->id])) {
                $clientsoftry[(int) $c->id] = $c;
            }
        }
        if (empty($clientsoftry)) {
            return false;
        }

        foreach ($clientsoftry as $clientrec) {
            $this->set_clientrecord($clientrec);
            $client = $this->get_oidcclient();

            $tokenparams = $client->rocredsrequest($oidcusername, $password);
            if (empty($tokenparams) || !isset($tokenparams['token_type']) || $tokenparams['token_type'] !== 'Bearer') {
                continue;
            }

            [$oidcuniqid, $idtoken] = $this->process_idtoken($tokenparams['id_token']);

            // Check restrictions.
            $passed = $this->checkrestrictions($idtoken);
            if ($passed !== true) {
                $errstr = 'User prevented from logging in due to restrictions.';
                utils::debug($errstr, __METHOD__, $idtoken);
                return false;
            }

            $tokenrec = $DB->get_record('auth_voidc_token', ['oidcuniqid' => $oidcuniqid]);
            if (!empty($tokenrec)) {
                $this->updatetoken($tokenrec->id, $authparams, $tokenparams);
            } else {
                // Resolve userid from the Moodle username explicitly. createtoken no
                // longer does this lookup itself (see base.php::createtoken comment),
                // so the password-grant flow must supply it. If no Moodle user exists
                // yet, pass 0 and let user_authenticated_hook backfill the userid
                // after the surrounding auth pipeline creates the account.
                $userrec = $DB->get_record('user', ['username' => $username, 'mnethostid' => $CFG->mnet_localhost_id]);
                $userid = !empty($userrec) ? (int) $userrec->id : 0;
                $this->createtoken($oidcuniqid, $username, $authparams, $tokenparams, $idtoken, $userid);
            }
            return true;
        }

        return false;
    }
}
