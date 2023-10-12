/**
 * The MIT License
 * Copyright (c) 2019- Nordic Institute for Interoperability Solutions (NIIS)
 * Copyright (c) 2018 Estonian Information System Authority (RIA),
 * Nordic Institute for Interoperability Solutions (NIIS), Population Register Centre (VRK)
 * Copyright (c) 2015-2017 Estonian Information System Authority (RIA), Population Register Centre (VRK)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.niis.xroad.securityserver.restapi.openapi;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.niis.xroad.restapi.config.audit.AuditEventMethod;
import org.niis.xroad.restapi.config.audit.RestApiAuditEvent;
import org.niis.xroad.restapi.exceptions.ErrorDeviation;
import org.niis.xroad.restapi.openapi.BadRequestException;
import org.niis.xroad.restapi.openapi.ControllerUtil;
import org.niis.xroad.restapi.openapi.ResourceNotFoundException;
import org.niis.xroad.restapi.service.UnhandledWarningsException;
import org.niis.xroad.restapi.util.FormatUtils;
import org.niis.xroad.securityserver.restapi.converter.BackupConverter;
import org.niis.xroad.securityserver.restapi.dto.BackupFile;
import org.niis.xroad.securityserver.restapi.openapi.model.Backup;
import org.niis.xroad.securityserver.restapi.openapi.model.BackupExt;
import org.niis.xroad.securityserver.restapi.openapi.model.TokensLoggedOut;
import org.niis.xroad.securityserver.restapi.service.BackupFileNotFoundException;
import org.niis.xroad.securityserver.restapi.service.BackupService;
import org.niis.xroad.securityserver.restapi.service.InvalidBackupFileException;
import org.niis.xroad.securityserver.restapi.service.InvalidFilenameException;
import org.niis.xroad.securityserver.restapi.service.RestoreProcessFailedException;
import org.niis.xroad.securityserver.restapi.service.RestoreService;
import org.niis.xroad.securityserver.restapi.service.TokenService;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.Set;

import static org.niis.xroad.restapi.exceptions.DeviationCodes.ERROR_BACKUP_RESTORE_INTERRUPTED;
import static org.niis.xroad.restapi.exceptions.DeviationCodes.ERROR_GENERATE_BACKUP_INTERRUPTED;

/**
 * Backups controller
 */
@Controller
@RequestMapping(ControllerUtil.API_V1_PREFIX)
@Slf4j
@PreAuthorize("denyAll")
@RequiredArgsConstructor
public class BackupsApiController implements BackupsApi {
    private final BackupService backupService;
    private final RestoreService restoreService;
    private final BackupConverter backupConverter;
    private final TokenService tokenService;

    @Override
    @PreAuthorize("hasAuthority('BACKUP_CONFIGURATION')")
    public ResponseEntity<Set<Backup>> getBackups() {
        List<BackupFile> backupFiles = backupService.getBackupFiles();

        return new ResponseEntity<>(backupConverter.convert(backupFiles), HttpStatus.OK);
    }

    @Override
    @PreAuthorize("hasAuthority('BACKUP_CONFIGURATION')")
    @AuditEventMethod(event = RestApiAuditEvent.DELETE_BACKUP)
    public ResponseEntity<Void> deleteBackup(String filename) {
        try {
            backupService.deleteBackup(filename);
        } catch (BackupFileNotFoundException e) {
            throw new ResourceNotFoundException(e);
        }

        return new ResponseEntity<>(HttpStatus.NO_CONTENT);
    }

    @Override
    @PreAuthorize("hasAuthority('BACKUP_CONFIGURATION')")
    public ResponseEntity<Resource> downloadBackup(String filename) {
        byte[] backupFile = null;
        try {
            backupFile = backupService.readBackupFile(filename);
        } catch (BackupFileNotFoundException e) {
            throw new ResourceNotFoundException(e);
        }
        return ControllerUtil.createAttachmentResourceResponse(backupFile, filename);
    }

    @Override
    @PreAuthorize("hasAuthority('BACKUP_CONFIGURATION')")
    @AuditEventMethod(event = RestApiAuditEvent.BACKUP)
    public ResponseEntity<Backup> addBackup() {
        try {
            BackupFile backupFile = backupService.generateBackup();
            return new ResponseEntity<>(backupConverter.convert(backupFile), HttpStatus.CREATED);
        } catch (InterruptedException e) {
            throw new InternalServerErrorException(new ErrorDeviation(ERROR_GENERATE_BACKUP_INTERRUPTED));
        }
    }

    @Override
    @PreAuthorize("hasAuthority('BACKUP_CONFIGURATION')")
    @AuditEventMethod(event = RestApiAuditEvent.BACKUP)
    public ResponseEntity<BackupExt> addBackupExt() {
        try {
            BackupFile backupFile = backupService.generateBackup();
            BackupExt backupExt = new BackupExt();
            backupExt.setBackup(backupConverter.convert(backupFile));
            backupExt.setLocalConfPresent((new File("/etc/xroad/services/local.conf")).exists());
            return new ResponseEntity<>(backupExt, HttpStatus.CREATED);
        } catch (InterruptedException e) {
            throw new InternalServerErrorException(new ErrorDeviation(ERROR_GENERATE_BACKUP_INTERRUPTED));
        }
    }

    @Override
    @PreAuthorize("hasAuthority('BACKUP_CONFIGURATION')")
    @AuditEventMethod(event = RestApiAuditEvent.UPLOAD_BACKUP)
    public ResponseEntity<Backup> uploadBackup(Boolean ignoreWarnings, MultipartFile file) {
        try {
            BackupFile backupFile = backupService.uploadBackup(ignoreWarnings, getValidOriginalFilename(file),
                    file.getBytes());
            return new ResponseEntity<>(backupConverter.convert(backupFile), HttpStatus.CREATED);
        } catch (InvalidFilenameException | UnhandledWarningsException | InvalidBackupFileException e) {
            throw new BadRequestException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    @PreAuthorize("hasAuthority('RESTORE_CONFIGURATION')")
    @AuditEventMethod(event = RestApiAuditEvent.RESTORE_BACKUP)
    public synchronized ResponseEntity<TokensLoggedOut> restoreBackup(String filename) {
        boolean hasHardwareTokens = tokenService.hasHardwareTokens();
        // If hardware tokens exist prior to the restore -> they will be logged out by the restore script
        TokensLoggedOut tokensLoggedOut = new TokensLoggedOut().hsmTokensLoggedOut(hasHardwareTokens);
        try {
            restoreService.restoreFromBackup(filename);
        } catch (BackupFileNotFoundException e) {
            throw new BadRequestException(e);
        } catch (InterruptedException e) {
            throw new InternalServerErrorException(new ErrorDeviation(ERROR_BACKUP_RESTORE_INTERRUPTED));
        } catch (RestoreProcessFailedException e) {
            throw new InternalServerErrorException(e);
        }
        return new ResponseEntity<>(tokensLoggedOut, HttpStatus.OK);
    }

    /**
     * Get original filename from Multipartfile, or throw {@link InvalidFilenameException}
     * if filename is not allowed
     * @param file
     * @return
     */
    private String getValidOriginalFilename(MultipartFile file) throws InvalidFilenameException {
        String filename = file.getOriginalFilename();
        validateFilename(filename);
        return filename;
    }

    private void validateFilename(String filename) throws InvalidFilenameException {
        if (!FormatUtils.isValidBackupFilename(filename)) {
            throw new InvalidFilenameException("invalid filename (" + filename + ")");
        }
    }
}
