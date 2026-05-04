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
 * Plugin upgrade script.
 *
 * @package auth_voidc
 * @author James McQuillan <james.mcquillan@remote-learner.net>
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->dirroot . '/auth/voidc/lib.php');

/**
 * Update plugin.
 *
 * @param int $oldversion the version we are upgrading from
 * @return bool result
 */
function xmldb_auth_voidc_upgrade($oldversion) {
    global $DB;

    $dbman = $DB->get_manager();

    if ($oldversion < 2014111703) {
        // Lengthen field.
        $table = new xmldb_table('auth_voidc_token');
        $field = new xmldb_field('scope', XMLDB_TYPE_CHAR, '255', null, XMLDB_NOTNULL, null, null, 'username');
        $dbman->change_field_type($table, $field);

        upgrade_plugin_savepoint(true, 2014111703, 'auth', 'voidc');
    }

    if ($oldversion < 2015012702) {
        $table = new xmldb_table('auth_voidc_state');
        $field = new xmldb_field('additionaldata', XMLDB_TYPE_TEXT, null, null, null, null, null, 'timecreated');
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }
        upgrade_plugin_savepoint(true, 2015012702, 'auth', 'voidc');
    }

    if ($oldversion < 2015012703) {
        $table = new xmldb_table('auth_voidc_token');
        $field = new xmldb_field('oidcusername', XMLDB_TYPE_CHAR, '255', null, XMLDB_NOTNULL, null, null, 'username');
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }
        upgrade_plugin_savepoint(true, 2015012703, 'auth', 'voidc');
    }

    if ($oldversion < 2015012704) {
        // Update OIDC users.
        $sql = 'SELECT u.id as userid,
                       u.username as username,
                       tok.id as tokenid,
                       tok.oidcuniqid as oidcuniqid,
                       tok.idtoken as idtoken,
                       tok.oidcusername as oidcusername
                  FROM {auth_voidc_token} tok
                  JOIN {user} u ON u.username = tok.username
                 WHERE u.auth = ? AND deleted = ?';
        $params = ['oidc', 0];
        $userstoupdate = $DB->get_recordset_sql($sql, $params);
        foreach ($userstoupdate as $user) {
            if (empty($user->idtoken)) {
                continue;
            }

            try {
                // Decode idtoken and determine oidc username.
                $idtoken = \auth_voidc\jwt::instance_from_encoded($user->idtoken);
                $oidcusername = $idtoken->claim('sub');

                // Populate token oidcusername.
                if (empty($user->oidcusername)) {
                    $updatedtoken = new stdClass;
                    $updatedtoken->id = $user->tokenid;
                    $updatedtoken->oidcusername = $oidcusername;
                    $DB->update_record('auth_voidc_token', $updatedtoken);
                }

                // Update user username (if applicable), so user can use rocreds loginflow.
                if ($user->username == strtolower($user->oidcuniqid)) {
                    // Old username, update to sub.
                    if ($oidcusername != $user->username) {
                        // Update username.
                        $updateduser = new stdClass;
                        $updateduser->id = $user->userid;
                        $updateduser->username = $oidcusername;
                        $DB->update_record('user', $updateduser);

                        $updatedtoken = new stdClass;
                        $updatedtoken->id = $user->tokenid;
                        $updatedtoken->username = $oidcusername;
                        $DB->update_record('auth_voidc_token', $updatedtoken);
                    }
                }
            } catch (moodle_exception $e) {
                continue;
            }
        }
        upgrade_plugin_savepoint(true, 2015012704, 'auth', 'voidc');
    }

    if ($oldversion < 2015012707) {
        if (!$dbman->table_exists('auth_voidc_prevlogin')) {
            $dbman->install_one_table_from_xmldb_file(__DIR__.'/install.xml', 'auth_voidc_prevlogin');
        }
        upgrade_plugin_savepoint(true, 2015012707, 'auth', 'voidc');
    }

    if ($oldversion < 2015012710) {
        // Lengthen field.
        $table = new xmldb_table('auth_voidc_token');
        $field = new xmldb_field('scope', XMLDB_TYPE_TEXT, null, null, null, null, null, 'oidcusername');
        $dbman->change_field_type($table, $field);
        upgrade_plugin_savepoint(true, 2015012710, 'auth', 'voidc');
    }

    if ($oldversion < 2015111904.01) {
        // Ensure the username field in auth_voidc_token is lowercase.
        $authtokensrs = $DB->get_recordset('auth_voidc_token');
        foreach ($authtokensrs as $authtokenrec) {
            $newusername = trim(\core_text::strtolower($authtokenrec->username));
            if ($newusername !== $authtokenrec->username) {
                $updatedrec = new stdClass;
                $updatedrec->id = $authtokenrec->id;
                $updatedrec->username = $newusername;
                $DB->update_record('auth_voidc_token', $updatedrec);
            }
        }
        upgrade_plugin_savepoint(true, 2015111904.01, 'auth', 'voidc');
    }

    // Savepoint for 2015111905.01 — endpoint migration removed.
    if ($oldversion < 2015111905.01) {
        upgrade_plugin_savepoint(true, 2015111905.01, 'auth', 'voidc');
    }

    if ($oldversion < 2018051700.01) {
        $table = new xmldb_table('auth_voidc_token');
        $field = new xmldb_field('userid', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, '0', 'username');
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
            $sql = 'SELECT tok.id, tok.username, u.username, u.id as userid
                      FROM {auth_voidc_token} tok
                      JOIN {user} u ON u.username = tok.username';
            $records = $DB->get_recordset_sql($sql);
            foreach ($records as $record) {
                $newrec = new stdClass;
                $newrec->id = $record->id;
                $newrec->userid = $record->userid;
                $DB->update_record('auth_voidc_token', $newrec);
            }
        }
        upgrade_plugin_savepoint(true, 2018051700.01, 'auth', 'voidc');
    }

    // Savepoint for 2020020301 — graph.windows.net migration removed.
    if ($oldversion < 2020020301) {
        upgrade_plugin_savepoint(true, 2020020301, 'auth', 'voidc');
    }

    // Savepoint for 2020071503 — single_sign_off migration removed.
    if ($oldversion < 2020071503) {
        upgrade_plugin_savepoint(true, 2020071503, 'auth', 'voidc');
    }

    if ($oldversion < 2020110901) {
        if ($dbman->field_exists('auth_voidc_token', 'resource')) {
            // Rename field resource on table auth_voidc_token to tokenresource.
            $table = new xmldb_table('auth_voidc_token');

            $field = new xmldb_field('resource', XMLDB_TYPE_CHAR, '127', null, XMLDB_NOTNULL, null, null, 'scope');

            // Launch rename field resource.
            $dbman->rename_field($table, $field, 'tokenresource');
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2020110901, 'auth', 'voidc');
    }

    if ($oldversion < 2020110903) {
        // Add index to auth_voidc_token table.
        $table = new xmldb_table('auth_voidc_token');

        // Define index userid (not unique) to be added to auth_voidc_token.
        $useridindex = new xmldb_index('userid', XMLDB_INDEX_NOTUNIQUE, ['userid']);

        // Conditionally launch add index userid.
        if (!$dbman->index_exists($table, $useridindex)) {
            $dbman->add_index($table, $useridindex);
        }

        // Define index username (not unique) to be added to auth_voidc_token.
        $usernameindex = new xmldb_index('username', XMLDB_INDEX_NOTUNIQUE, ['username']);

        // Conditionally launch add index username.
        if (!$dbman->index_exists($table, $usernameindex)) {
            $dbman->add_index($table, $usernameindex);
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2020110903, 'auth', 'voidc');
    }

    // Savepoint for 2021051701 — field mapping migration removed.
    if ($oldversion < 2021051701) {
        upgrade_plugin_savepoint(true, 2021051701, 'auth', 'voidc');
    }

    if ($oldversion < 2022041901) {
        // Define field sid to be added to auth_voidc_token.
        $table = new xmldb_table('auth_voidc_token');
        $field = new xmldb_field('sid', XMLDB_TYPE_CHAR, '36', null, null, null, null, 'idtoken');

        // Conditionally launch add field sid.
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2022041901, 'auth', 'voidc');
    }

    // Savepoint for 2022041906 — idptype/clientauthmethod/tenantnameorguid migrations removed.
    if ($oldversion < 2022041906) {
        upgrade_plugin_savepoint(true, 2022041906, 'auth', 'voidc');
    }

    if ($oldversion < 2022112801) {
        // Update tenantnameorguid config.
        unset_config('auth_voidc', 'tenantnameorguid');

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2022112801, 'auth', 'voidc');
    }

    // Savepoint for 2023100902 — clientcertsource certificate migration removed.
    if ($oldversion < 2023100902) {
        upgrade_plugin_savepoint(true, 2023100902, 'auth', 'voidc');
    }

    if ($oldversion < 2024042201) {
        // Set default values for new settings "bindingusernameclaim" and "customclaimname".
        if (!get_config('auth_voidc', 'bindingusernameclaim')) {
            set_config('bindingusernameclaim', 'auto', 'auth_voidc');
        }

        if (!get_config('auth_voidc', 'customclaimname')) {
            set_config('customclaimname', '', 'auth_voidc');
        }

        // Define field useridentifier to be added to auth_voidc_token.
        $table = new xmldb_table('auth_voidc_token');
        $field = new xmldb_field('useridentifier', XMLDB_TYPE_CHAR, '255', null, null, null, null, 'oidcusername');

        // Conditionally launch add field useridentifier.
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);

            // Save current value of oidcusername to useridentifier.
            $sql = 'UPDATE {auth_voidc_token} SET useridentifier = oidcusername';
            $DB->execute($sql);
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2024042201, 'auth', 'voidc');
    }

    if ($oldversion < 2024100701) {
        // Set the default value for the bindingusernameclaim setting.
        $bindingusernameclaimconfig = get_config('auth_voidc', 'bindingusernameclaim');
        if (empty($bindingusernameclaimconfig)) {
            set_config('bindingusernameclaim', 'auto', 'auth_voidc');
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2024100701, 'auth', 'voidc');
    }

    if ($oldversion < 2024100702) {
        // Define table auth_voidc_sid to be created.
        $table = new xmldb_table('auth_voidc_sid');

        // Adding fields to table auth_voidc_sid.
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('userid', XMLDB_TYPE_INTEGER, '20', null, XMLDB_NOTNULL, null, null);
        $table->add_field('sid', XMLDB_TYPE_CHAR, '36', null, XMLDB_NOTNULL, null, null);
        $table->add_field('timecreated', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);

        // Adding keys to table auth_voidc_sid.
        $table->add_key('primary', XMLDB_KEY_PRIMARY, ['id']);

        // Conditionally launch create table for auth_voidc_sid.
        if (!$dbman->table_exists($table)) {
            $dbman->create_table($table);
        }

        // Migrate existing sid values from auth_voidc_tokens to auth_voidc_sid.
        if ($dbman->field_exists('auth_voidc_token', 'sid')) {
            $sql = "INSERT INTO {auth_voidc_sid} (userid, sid, timecreated)
                    SELECT userid, sid, ? AS timecreated
                    FROM {auth_voidc_token}
                    WHERE sid IS NOT NULL AND sid != ''";
            $DB->execute($sql, [time()]);
        }

        // Define field sid to be dropped from auth_voidc_token.
        $table = new xmldb_table('auth_voidc_token');
        $field = new xmldb_field('sid');

        // Conditionally launch drop field sid.
        if ($dbman->field_exists($table, $field)) {
            $dbman->drop_field($table, $field);
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2024100702, 'auth', 'voidc');
    }

    if ($oldversion < 2026040800) {
        // Define table auth_voidc_clients to be created.
        $table = new xmldb_table('auth_voidc_clients');

        // Adding fields to table auth_voidc_clients.
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('name', XMLDB_TYPE_CHAR, '255', null, XMLDB_NOTNULL, null, null);
        $table->add_field('departmentid', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, '0');
        $table->add_field('groupid', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, '0');
        $table->add_field('idptype', XMLDB_TYPE_INTEGER, '2', null, XMLDB_NOTNULL, null, '0');
        $table->add_field('clientid', XMLDB_TYPE_CHAR, '255', null, XMLDB_NOTNULL, null, null);
        $table->add_field('clientauthmethod', XMLDB_TYPE_INTEGER, '2', null, XMLDB_NOTNULL, null, '1');
        $table->add_field('clientsecret', XMLDB_TYPE_TEXT, null, null, null, null, null);
        $table->add_field('clientprivatekey', XMLDB_TYPE_TEXT, null, null, null, null, null);
        $table->add_field('clientcert', XMLDB_TYPE_TEXT, null, null, null, null, null);
        $table->add_field('authendpoint', XMLDB_TYPE_TEXT, null, null, XMLDB_NOTNULL, null, null);
        $table->add_field('tokenendpoint', XMLDB_TYPE_TEXT, null, null, XMLDB_NOTNULL, null, null);
        $table->add_field('oidcresource', XMLDB_TYPE_CHAR, '255', null, null, null, null);
        $table->add_field('oidcscope', XMLDB_TYPE_CHAR, '255', null, XMLDB_NOTNULL, null, 'openid profile email');
        $table->add_field('icon', XMLDB_TYPE_CHAR, '255', null, null, null, null);
        $table->add_field('sortorder', XMLDB_TYPE_INTEGER, '5', null, XMLDB_NOTNULL, null, '0');
        $table->add_field('enabled', XMLDB_TYPE_INTEGER, '1', null, XMLDB_NOTNULL, null, '1');
        $table->add_field('timecreated', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);
        $table->add_field('timemodified', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, null);

        // Adding keys to table auth_voidc_clients.
        $table->add_key('primary', XMLDB_KEY_PRIMARY, ['id']);

        // Adding indexes to table auth_voidc_clients.
        $table->add_index('enabled', XMLDB_INDEX_NOTUNIQUE, ['enabled']);
        $table->add_index('sortorder', XMLDB_INDEX_NOTUNIQUE, ['sortorder']);

        // Conditionally launch create table for auth_voidc_clients.
        if (!$dbman->table_exists($table)) {
            $dbman->create_table($table);
        }

        // Define field clientid to be added to auth_voidc_token.
        $table = new xmldb_table('auth_voidc_token');
        $field = new xmldb_field('clientid', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, '0', 'idtoken');

        // Conditionally launch add field clientid.
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }

        // Define index clientid (not unique) to be added to auth_voidc_token.
        $index = new xmldb_index('clientid', XMLDB_INDEX_NOTUNIQUE, ['clientid']);

        // Conditionally launch add index clientid.
        if (!$dbman->index_exists($table, $index)) {
            $dbman->add_index($table, $index);
        }

        // Define field clientid to be added to auth_voidc_state.
        $table = new xmldb_table('auth_voidc_state');
        $field = new xmldb_field('clientid', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, '0', 'additionaldata');

        // Conditionally launch add field clientid.
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2026040800, 'auth', 'voidc');
    }

    if ($oldversion < 2026040900) {
        // Per-client binding username claim.
        $table = new xmldb_table('auth_voidc_clients');

        $field = new xmldb_field('bindingusernameclaim', XMLDB_TYPE_CHAR, '64', null, XMLDB_NOTNULL, null, 'auto',
            'oidcscope');
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }

        $field = new xmldb_field('customclaimname', XMLDB_TYPE_CHAR, '128', null, null, null, null,
            'bindingusernameclaim');
        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2026040900, 'auth', 'voidc');
    }

    if ($oldversion < 2026041000) {
        // Add per-client logout endpoint.
        $table = new xmldb_table('auth_voidc_clients');
        $field = new xmldb_field('logoutendpoint', XMLDB_TYPE_TEXT, null, null, null, null, null, 'customclaimname');

        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2026041000, 'auth', 'voidc');
    }

    if ($oldversion < 2026050200) {
        // Add required department mapping per client.
        $table = new xmldb_table('auth_voidc_clients');
        $field = new xmldb_field('departmentid', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, '0', 'name');

        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2026050200, 'auth', 'voidc');
    }

    if ($oldversion < 2026050300) {
        // Add required group mapping per client.
        $table = new xmldb_table('auth_voidc_clients');
        $field = new xmldb_field('groupid', XMLDB_TYPE_INTEGER, '10', null, XMLDB_NOTNULL, null, '0', 'departmentid');

        if (!$dbman->field_exists($table, $field)) {
            $dbman->add_field($table, $field);
        }

        // Voidc savepoint reached.
        upgrade_plugin_savepoint(true, 2026050300, 'auth', 'voidc');
    }

    return true;
}
