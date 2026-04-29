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
 * SSO method selector page for auth_voidc.
 *
 * @package auth_voidc
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

// phpcs:ignore moodle.Files.RequireLogin.Missing
require_once(__DIR__ . '/../../../config.php');
require_once(__DIR__ . '/../lib.php');

global $DB, $OUTPUT, $PAGE;

$query = trim(optional_param('q', '', PARAM_TEXT));

$PAGE->set_url(new moodle_url('/auth/voidc/controller/sso_method_selector.php'));
$PAGE->set_context(context_system::instance());
$PAGE->set_pagelayout('embedded');
$PAGE->set_title(get_string('pluginname', 'auth_voidc'));
$PAGE->requires->css(new moodle_url('/auth/voidc/scss/sso_method_selector.css'));

$providers = [];
$clients = $DB->get_records('auth_voidc_clients', ['enabled' => 1], 'sortorder ASC, id ASC');
foreach ($clients as $client) {
    $name = trim(strip_tags(format_string($client->name)));
    if ($query !== '' && stripos($name, $query) === false) {
        continue;
    }

    $iconurl = auth_voidc_get_client_icon_url((int) $client->id);
    if ($iconurl) {
        $iconhtml = html_writer::empty_tag('img', [
            'src' => $iconurl->out(false),
            'alt' => s($client->name),
        ]);
    } else {
        $iconhtml = $OUTPUT->pix_icon('i/mnethost', s($client->name));
    }

    $providers[] = [
        'name' => $name,
        'url' => (new moodle_url('/auth/voidc/', ['source' => 'loginpage', 'cid' => $client->id]))->out(false),
        'iconhtml' => $iconhtml,
    ];
}

$templatepath = __DIR__ . '/../templates/sso_method_selector.mustache';
if (!is_readable($templatepath)) {
    throw new moodle_exception('errorauthgeneral', 'auth_voidc');
}
$templatecontent = file_get_contents($templatepath);

$context = [
    'backurl' => (new moodle_url('/login/index.php'))->out(false),
    'backlabel' => get_string('sso_selector_backlabel', 'auth_voidc'),
    'title' => get_string('sso_selector_title', 'auth_voidc'),
    'searchquery' => $query,
    'searchplaceholder' => get_string('sso_selector_searchplaceholder', 'auth_voidc'),
    'emptylabel' => get_string('sso_selector_empty', 'auth_voidc'),
    'brandlogo' => '/theme/vloom/pix/edrapath-logo.svg',
    'brandalt' => get_string('sso_selector_brandalt', 'auth_voidc'),
    'providers' => array_values($providers),
];

echo $OUTPUT->header();
$mustache = new Mustache_Engine();
echo $mustache->render($templatecontent, $context);
echo $OUTPUT->footer();
