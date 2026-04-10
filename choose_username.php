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
 * Choose-a-new-username page for voidc signup collisions.
 *
 * Reached when a new voidc signup's derived username collides with an existing
 * Moodle account. We stashed the verified IdP state in $SESSION just before
 * redirecting here; this page lets the user pick a unique name and then
 * finishes the signup (create user + token + login) using that stashed state.
 *
 * @package auth_voidc
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

// phpcs:ignore moodle.Files.RequireLogin.Missing
require_once(__DIR__ . '/../../config.php');
require_once(__DIR__ . '/auth.php');
require_once(__DIR__ . '/lib.php');

use auth_voidc\form\choose_username;
use auth_voidc\jwt;
use core\output\notification;

// How long a pending signup can sit in the session before we drop it.
const AUTH_VOIDC_PENDING_SIGNUP_TTL = 10 * MINSECS;

$url = new moodle_url('/auth/voidc/choose_username.php');
$PAGE->set_url($url);
$PAGE->set_context(context_system::instance());
$PAGE->set_pagelayout('login');
$PAGE->set_title(get_string('choose_username_pagetitle', 'auth_voidc'));
$PAGE->set_heading(get_string('choose_username_heading', 'auth_voidc'));

$loginurl = new moodle_url('/login/index.php');

// Must have a pending signup in the session to be on this page at all.
$pending = $SESSION->auth_voidc_pending_signup ?? null;
if (empty($pending) || empty($pending->oidcuniqid) || empty($pending->tokenparams)) {
    redirect($loginurl, get_string('choose_username_missing', 'auth_voidc'),
        null, notification::NOTIFY_ERROR);
}

// Expire stale signups - don't let someone come back hours later and finish
// a signup with tokens they never controlled.
if (empty($pending->created) || (time() - (int) $pending->created) > AUTH_VOIDC_PENDING_SIGNUP_TTL) {
    unset($SESSION->auth_voidc_pending_signup);
    redirect($loginurl, get_string('choose_username_expired', 'auth_voidc'),
        null, notification::NOTIFY_ERROR);
}

$form = new choose_username($url->out(false), [
    'collided' => $pending->collided ?? '',
    'suggested' => $pending->suggested ?? '',
]);

if ($form->is_cancelled()) {
    unset($SESSION->auth_voidc_pending_signup);
    redirect($loginurl, get_string('choose_username_cancelled', 'auth_voidc'),
        null, notification::NOTIFY_INFO);
}

if ($data = $form->get_data()) {
    $chosenusername = \core_text::strtolower(trim((string) $data->username));

    // Rehydrate the clientrecord and idtoken from the stashed state.
    $clientrec = auth_voidc_get_client((int) $pending->clientid);
    if (empty($clientrec) || empty($clientrec->enabled)) {
        unset($SESSION->auth_voidc_pending_signup);
        redirect($loginurl, get_string('errorunknownclient', 'auth_voidc'),
            null, notification::NOTIFY_ERROR);
    }

    $tokenparams = (array) $pending->tokenparams;
    $authparams = (array) ($pending->authparams ?? []);
    if (empty($tokenparams['id_token'])) {
        unset($SESSION->auth_voidc_pending_signup);
        redirect($loginurl, get_string('errorauthinvalididtoken', 'auth_voidc'),
            null, notification::NOTIFY_ERROR);
    }

    $idtoken = jwt::instance_from_encoded($tokenparams['id_token']);

    // Instantiate the authcode loginflow and prime it with the rehydrated client.
    $auth = new auth_plugin_voidc('authcode');
    $auth->set_httpclient(new \auth_voidc\httpclient());
    $auth->loginflow->set_clientrecord($clientrec);

    try {
        [$user, $tokenrec] = $auth->loginflow->finalize_new_user_signup(
            (string) $pending->oidcuniqid,
            $chosenusername,
            $authparams,
            $tokenparams,
            $idtoken
        );
    } catch (moodle_exception $e) {
        // Policy failure (authpreventaccountcreation / dup email) - bubble up
        // with a clear message and drop the pending state so the user can't
        // retry the same payload in a loop.
        unset($SESSION->auth_voidc_pending_signup);
        throw $e;
    }

    // Pending state has served its purpose - burn it before completing login
    // so it can't be reused by a later request.
    unset($SESSION->auth_voidc_pending_signup);

    // Don't route through authenticate_user_login() here. authcode::user_login()
    // verifies the current request's 'code' query parameter matches the token
    // row's authcode - that check is designed for the OIDC redirect leg, not
    // for a plain form POST like this one, and it will always fail here. We
    // just created the user and the token ourselves, so we can complete the
    // Moodle login directly. Invoke user_authenticated_hook manually so the
    // auth_voidc user_loggedin event still fires.
    $freshuser = $DB->get_record('user', ['id' => $user->id], '*', MUST_EXIST);
    $auth->user_authenticated_hook($freshuser, $chosenusername, '');
    complete_user_login($freshuser);

    // Honour wantsurl if the original login flow captured one, otherwise
    // drop the user at the site home.
    if (!empty($SESSION->wantsurl) && strpos($SESSION->wantsurl, $CFG->wwwroot) === 0) {
        $urltogo = $SESSION->wantsurl;
        unset($SESSION->wantsurl);
    } else {
        $urltogo = new moodle_url('/');
    }
    redirect($urltogo);
}

echo $OUTPUT->header();
echo $OUTPUT->heading(get_string('choose_username_heading', 'auth_voidc'));
$form->display();
echo $OUTPUT->footer();
