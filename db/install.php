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
 * Plugin installation script.
 *
 * @package auth_voidc
 * @author Lai Wei <lai.wei@enovation.ie>
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 * @copyright (C) 2024 onwards Videa Edtech Ltd.
 */

/**
 * Installation script.
 */
function xmldb_auth_voidc_install() {
    // Set the default value for the bindingusernameclaim setting.
    $bindingusernameclaimconfig = get_config('auth_voidc', 'bindingusernameclaim');
    if (empty($bindingusernameclaimconfig)) {
        set_config('bindingusernameclaim', 'preferred_username', 'auth_voidc');
    }

    // Set the default value for the field_map_email setting.
    $fieldmapemail = get_config('auth_voidc', 'field_map_email');
    if (empty($fieldmapemail)) {
        set_config('field_map_email', 'mail', 'auth_voidc');
    }

    // Set the default value for the field_map_firstname setting.
    $fieldmapfirstname = get_config('auth_voidc', 'field_map_firstname');
    if (empty($fieldmapfirstname)) {
        set_config('field_map_firstname', 'givenName', 'auth_voidc');
    }

    // Set the default value for the field_map_lastname setting.
    $fieldmaplastname = get_config('auth_voidc', 'field_map_lastname');
    if (empty($fieldmaplastname)) {
        set_config('field_map_lastname', 'surname', 'auth_voidc');
    }
}
